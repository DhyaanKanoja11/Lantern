package reclaim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/docker"
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// TargetType classifies what entity occupies the port.
type TargetType string

const (
	TargetContainer TargetType = "CONTAINER"
	TargetProcess   TargetType = "PROCESS"
	TargetUnknown   TargetType = "UNKNOWN"
)

// ReclaimPlan describes the entity occupying the port and the planned free action.
type ReclaimPlan struct {
	Port          uint16     `json:"port"`
	TargetType    TargetType `json:"target_type"`
	ContainerID   string     `json:"container_id,omitempty"`
	ContainerName string     `json:"container_name,omitempty"`
	Image         string     `json:"image,omitempty"`
	Project       string     `json:"project,omitempty"`
	Service       string     `json:"service,omitempty"`
	PID           int        `json:"pid,omitempty"`
	ProcessName   string     `json:"process_name,omitempty"`
	CommandLine   string     `json:"command_line,omitempty"`
	User          string     `json:"user,omitempty"`
}

// ReclaimResult describes the outcome of a successful reclaim operation.
type ReclaimResult struct {
	Port        uint16     `json:"port"`
	TargetType  TargetType `json:"target_type"`
	Identifier  string     `json:"identifier"`
	Description string     `json:"description"`
}

// ProcessKiller defines the function signature for process termination.
type ProcessKiller func(pid int, force bool, gracePeriod time.Duration) error

// ContainerStopper defines the function signature for container stopping.
type ContainerStopper func(ctx context.Context, id string, timeoutSeconds int) error

// Reclaimer defines the interface for planning and freeing occupied ports.
type Reclaimer interface {
	Plan(ctx context.Context, exp *domain.Exposure) (*ReclaimPlan, error)
	Apply(ctx context.Context, plan *ReclaimPlan, force bool, timeout time.Duration) (*ReclaimResult, error)
}

// DefaultReclaimer coordinates port reclaim operations using Docker and OS primitives.
type DefaultReclaimer struct {
	stopContainer ContainerStopper
	killProcess   ProcessKiller
	getSelfPID    func() int
}

// NewDefaultReclaimer constructs a Reclaimer with production defaults.
func NewDefaultReclaimer() *DefaultReclaimer {
	cli := docker.NewDefaultCorrelator()
	return &DefaultReclaimer{
		stopContainer: cli.StopContainer,
		killProcess:   defaultProcessKiller,
		getSelfPID:    os.Getpid,
	}
}

// NewReclaimerWithDeps constructs a Reclaimer with injectable dependencies for hermetic testing.
func NewReclaimerWithDeps(stopper ContainerStopper, killer ProcessKiller, selfPID func() int) *DefaultReclaimer {
	if selfPID == nil {
		selfPID = os.Getpid
	}
	return &DefaultReclaimer{
		stopContainer: stopper,
		killProcess:   killer,
		getSelfPID:    selfPID,
	}
}

// Plan analyzes an exposure to identify the target entity occupying the port.
func (r *DefaultReclaimer) Plan(ctx context.Context, exp *domain.Exposure) (*ReclaimPlan, error) {
	if exp == nil {
		return nil, errors.New("exposure cannot be nil")
	}

	plan := &ReclaimPlan{
		Port: exp.Port,
	}

	// 1. Check for Docker Container target
	if exp.Container != nil {
		plan.TargetType = TargetContainer
		plan.ContainerID = exp.Container.ID
		plan.ContainerName = strings.TrimPrefix(exp.Container.Name, "/")
		plan.Image = exp.Container.Image
		if exp.Container.Labels != nil {
			plan.Project = exp.Container.Labels["com.docker.compose.project"]
			plan.Service = exp.Container.Labels["com.docker.compose.service"]
		}
		if exp.Container.HostPID > 0 {
			plan.PID = exp.Container.HostPID
		} else if exp.Listener.PID > 0 {
			plan.PID = exp.Listener.PID
		}
		return plan, nil
	}

	// 2. Check for Native Process target
	targetPID := 0
	if exp.Process != nil && exp.Process.PID > 0 {
		targetPID = exp.Process.PID
	} else if exp.Listener.PID > 0 {
		targetPID = exp.Listener.PID
	}

	if isDockerProxy(exp) {
		// The port is Docker's, but we couldn't work out which container
		// published it (daemon unreachable, ambiguous mapping...). Killing
		// docker-proxy itself would break Docker networking, so stop here.
		return nil, fmt.Errorf("port %d is held by docker-proxy but the owning container could not be identified; stop the container with docker instead", exp.Port)
	}

	if targetPID > 0 {
		plan.TargetType = TargetProcess
		plan.PID = targetPID
		if exp.Process != nil {
			plan.ProcessName = exp.Process.Name
			plan.CommandLine = exp.Process.CommandLine
			plan.User = exp.Process.User
		}
		if plan.ProcessName == "" && exp.Listener.ProcessName != "" {
			plan.ProcessName = exp.Listener.ProcessName
		}
		return plan, nil
	}

	// 3. Fallback: Unknown listener (unprivileged or missing metadata)
	plan.TargetType = TargetUnknown
	return plan, nil
}

// Apply executes the reclaim plan to free the port.
func (r *DefaultReclaimer) Apply(ctx context.Context, plan *ReclaimPlan, force bool, timeout time.Duration) (*ReclaimResult, error) {
	if plan == nil {
		return nil, errors.New("reclaim plan cannot be nil")
	}

	switch plan.TargetType {
	case TargetContainer:
		if plan.ContainerID == "" && plan.ContainerName == "" {
			return nil, errors.New("cannot stop container: missing container ID and name")
		}
		target := plan.ContainerID
		if target == "" {
			target = plan.ContainerName
		}

		timeoutSec := int(timeout.Seconds())
		if timeoutSec <= 0 {
			timeoutSec = 10
		}

		if err := r.stopContainer(ctx, target, timeoutSec); err != nil {
			return nil, fmt.Errorf("failed to stop container %s: %w", target, err)
		}

		name := plan.ContainerName
		if name == "" {
			name = plan.ContainerID
		}

		return &ReclaimResult{
			Port:        plan.Port,
			TargetType:  TargetContainer,
			Identifier:  name,
			Description: fmt.Sprintf("Docker container %q stopped", name),
		}, nil

	case TargetProcess:
		if plan.PID <= 0 {
			return nil, errors.New("cannot terminate process: invalid or unknown PID")
		}

		// Security Guardrail: Prevent killing PID 1 or self PID
		if plan.PID <= 1 {
			return nil, fmt.Errorf("refusing to terminate system process (PID %d)", plan.PID)
		}
		if r.getSelfPID != nil && plan.PID == r.getSelfPID() {
			return nil, fmt.Errorf("refusing to terminate self (PID %d)", plan.PID)
		}

		gracePeriod := timeout / 2
		if gracePeriod < 200*time.Millisecond {
			gracePeriod = 500 * time.Millisecond
		}

		if err := r.killProcess(plan.PID, force, gracePeriod); err != nil {
			return nil, fmt.Errorf("failed to terminate process %d (%s): %w", plan.PID, plan.ProcessName, err)
		}

		procDesc := plan.ProcessName
		if procDesc == "" {
			procDesc = fmt.Sprintf("PID %d", plan.PID)
		} else {
			procDesc = fmt.Sprintf("%q (PID %d)", procDesc, plan.PID)
		}

		return &ReclaimResult{
			Port:        plan.Port,
			TargetType:  TargetProcess,
			Identifier:  strconv.Itoa(plan.PID),
			Description: fmt.Sprintf("Process %s terminated", procDesc),
		}, nil

	case TargetUnknown:
		return nil, fmt.Errorf("cannot free port %d: listener process is unknown (run with elevated privileges or sudo to inspect unprivileged sockets)", plan.Port)

	default:
		return nil, fmt.Errorf("unsupported reclaim target type: %q", plan.TargetType)
	}
}

// isDockerProxy reports whether the listener looks like Docker's userland proxy.
func isDockerProxy(exp *domain.Exposure) bool {
	names := []string{exp.Listener.ProcessName}
	if exp.Process != nil {
		names = append(names, exp.Process.Name)
		if fields := strings.Fields(exp.Process.CommandLine); len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(filepath.Base(n), ".exe"))
		if n == "docker-proxy" {
			return true
		}
	}
	return false
}
