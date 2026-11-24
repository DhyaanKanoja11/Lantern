package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// CommandRunner defines the function signature for executing CLI commands.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// CLIClient implements DockerCorrelator using the system `docker` CLI.
type CLIClient struct {
	runner   CommandRunner
	lookPath func(file string) (string, error)
}

// NewCLIClient creates a new CLIClient with the default exec runner.
func NewCLIClient() *CLIClient {
	return NewCLIClientWithRunner(defaultCommandRunner)
}

// NewCLIClientWithRunner allows injecting a custom CommandRunner for deterministic testing.
func NewCLIClientWithRunner(runner CommandRunner) *CLIClient {
	return &CLIClient{runner: runner, lookPath: exec.LookPath}
}

// SetLookPath allows overriding the lookPath resolver in hermetic tests.
func (c *CLIClient) SetLookPath(lp func(file string) (string, error)) {
	c.lookPath = lp
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// CheckDaemon checks whether the Docker CLI is installed and the daemon is reachable.
// Returns typed errors distinguishing daemon stopped, socket missing, permission denied,
// or executable missing.
func (c *CLIClient) CheckDaemon(ctx context.Context) error {
	look := c.lookPath
	if look == nil {
		look = exec.LookPath
	}
	_, err := look("docker")
	if err != nil {
		return ErrDockerNotAvailable
	}
	_, err = c.runner(ctx, "docker", "ps", "-q")
	if err != nil {
		return wrapDockerError(err)
	}
	return nil
}

// IsAvailable checks whether the docker CLI is present and the daemon is responsive.
func (c *CLIClient) IsAvailable(ctx context.Context) bool {
	return c.CheckDaemon(ctx) == nil
}

// ListContainers lists all currently running Docker containers with detailed metadata.
func (c *CLIClient) ListContainers(ctx context.Context) ([]domain.Container, error) {
	out, err := c.runner(ctx, "docker", "ps", "-q", "--no-trunc")
	if err != nil {
		return nil, wrapDockerError(err)
	}

	ids := ParseContainerIDs(out)
	if len(ids) == 0 {
		return nil, nil
	}

	// Batch inspect all running container IDs
	inspectArgs := append([]string{"inspect"}, ids...)
	inspectOut, err := c.runner(ctx, "docker", inspectArgs...)
	if err != nil {
		// A container may have exited between list and inspect; fall back to inspecting individually
		var recovered []domain.Container
		for _, id := range ids {
			singleOut, singleErr := c.runner(ctx, "docker", "inspect", id)
			if singleErr == nil {
				if parsed, parseErr := ParseInspectOutput(singleOut); parseErr == nil && len(parsed) > 0 {
					recovered = append(recovered, parsed...)
				}
			}
		}
		return recovered, nil
	}

	return ParseInspectOutput(inspectOut)
}

// InspectContainer inspects a single container by ID or name.
func (c *CLIClient) InspectContainer(ctx context.Context, id string) (*domain.Container, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("empty container ID")
	}

	out, err := c.runner(ctx, "docker", "inspect", id)
	if err != nil {
		return nil, wrapDockerError(err)
	}

	containers, err := ParseInspectOutput(out)
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, ErrContainerNotFound
	}

	return &containers[0], nil
}

// StopContainer cleanly stops a running container by ID or name with an optional timeout.
func (c *CLIClient) StopContainer(ctx context.Context, id string, timeoutSeconds int) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("empty container ID")
	}

	args := []string{"stop"}
	if timeoutSeconds > 0 {
		args = append(args, "-t", strconv.Itoa(timeoutSeconds))
	}
	args = append(args, id)

	_, err := c.runner(ctx, "docker", args...)
	if err != nil {
		return wrapDockerError(err)
	}
	return nil
}

// CorrelatePID correlates a host listener PID with a Docker container's Host PID.
func (c *CLIClient) CorrelatePID(ctx context.Context, pid int) (*domain.Container, *domain.PortMapping, error) {
	if pid <= 0 {
		return nil, nil, ErrContainerNotFound
	}

	containers, err := c.ListContainers(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, container := range containers {
		if container.HostPID == pid {
			cCopy := container
			cCopy.AttributionMode = domain.AttributionDirect
			var mCopy *domain.PortMapping
			if len(cCopy.Ports) > 0 {
				m := cCopy.Ports[0]
				mCopy = &m
			}
			return &cCopy, mCopy, nil
		}
	}

	return nil, nil, ErrContainerNotFound
}

type candidateMatch struct {
	container domain.Container
	mapping   domain.PortMapping
	score     int // 2 for exact host-IP match, 1 for wildcard match
}

func normalizeIPString(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "[]")
	if addr == "" || addr == "*" {
		return "0.0.0.0"
	}
	if strings.HasPrefix(strings.ToLower(addr), "::ffff:") {
		mapped := addr[7:]
		if net.ParseIP(mapped) != nil {
			return mapped
		}
	}
	return addr
}

// matchAddressScore scores compatibility between listener address and Docker published host IP.
// 2 = exact specific match, 1 = exact wildcard match (same family), 0 = no match or cross-family mismatch.
func matchAddressScore(listenerAddr, mappingIP string) int {
	listenerAddr = normalizeIPString(listenerAddr)
	mappingIP = normalizeIPString(mappingIP)

	lIP := net.ParseIP(listenerAddr)
	mIP := net.ParseIP(mappingIP)

	if lIP == nil || mIP == nil {
		if strings.EqualFold(listenerAddr, mappingIP) {
			return 2
		}
		return 0
	}

	lIsV4 := lIP.To4() != nil
	mIsV4 := mIP.To4() != nil

	// Cross-family matching (IPv4 vs IPv6 wildcard) is strictly prohibited unless verified.
	if lIsV4 != mIsV4 {
		return 0
	}

	// Must be equivalent IP (via net.IP.Equal)
	if !lIP.Equal(mIP) {
		return 0
	}

	// Wildcard match within same family (e.g. 0.0.0.0 vs 0.0.0.0 or :: vs ::)
	if lIP.IsUnspecified() && mIP.IsUnspecified() {
		return 1
	}

	// Specific IP match (e.g. 127.0.0.1 vs 127.0.0.1)
	return 2
}

// CorrelatePort finds a running container that published the specified host address and port (defaults to TCP).
// Returns ErrAmbiguousMapping if multiple containers match the same listener address and port.
func (c *CLIClient) CorrelatePort(ctx context.Context, address string, port uint16) (*domain.Container, *domain.PortMapping, error) {
	return c.CorrelatePortProto(ctx, "tcp", address, port)
}

// CorrelatePortProto finds a running container that published the specified protocol, host address, and port.
// Returns ErrAmbiguousMapping if multiple running containers match the same listener criteria.
func (c *CLIClient) CorrelatePortProto(ctx context.Context, proto, address string, port uint16) (*domain.Container, *domain.PortMapping, error) {
	if port == 0 {
		return nil, nil, ErrContainerNotFound
	}
	if proto == "" {
		proto = "tcp"
	}

	containers, err := c.ListContainers(ctx)
	if err != nil {
		return nil, nil, err
	}

	var candidates []candidateMatch
	for _, container := range containers {
		// Only running containers can own an active host listener socket
		if !container.Running {
			continue
		}
		for _, p := range container.Ports {
			// Protocol validation: match protocol when declared
			if p.Protocol != "" && !strings.EqualFold(p.Protocol, proto) {
				continue
			}
			if p.HostPort == port {
				score := matchAddressScore(address, p.HostIP)
				if score > 0 {
					candidates = append(candidates, candidateMatch{
						container: container,
						mapping:   p,
						score:     score,
					})
				}
			}
		}
	}

	if len(candidates) == 0 {
		return nil, nil, ErrContainerNotFound
	}

	// Find the highest score among candidates (prefer exact match over wildcard)
	maxScore := 0
	for _, cand := range candidates {
		if cand.score > maxScore {
			maxScore = cand.score
		}
	}

	var bestMatches []candidateMatch
	containerIDs := make(map[string]bool)
	for _, cand := range candidates {
		if cand.score == maxScore {
			bestMatches = append(bestMatches, cand)
			containerIDs[cand.container.ID] = true
		}
	}

	// If more than one container matches with the same best specificity, correlation is ambiguous
	if len(containerIDs) > 1 {
		return nil, nil, ErrAmbiguousMapping
	}

	cCopy := bestMatches[0].container
	pCopy := bestMatches[0].mapping
	return &cCopy, &pCopy, nil
}

// CorrelateListener correlates a listener with a container using the 5-state attribution engine:
// State 1: PID > 0, identified native process (not docker-proxy) -> fail-closed (ErrContainerNotFound)
// State 2: PID > 0, verified docker-proxy process -> DIRECT attribution via published port
// State 3: PID > 0, uninspected/unknown process -> fail-closed (ErrContainerNotFound)
// State 4: PID == 0, unprivileged Linux listener ("" or "unknown" or "docker-proxy") -> INFERRED attribution
// State 5: PID == 0, identified native process -> fail-closed (ErrContainerNotFound)
func (c *CLIClient) CorrelateListener(ctx context.Context, l domain.Listener) (*domain.Container, *domain.PortMapping, error) {
	proto := l.Protocol
	if proto == "" {
		proto = "tcp"
	}

	// 1. If PID > 0:
	if l.PID > 0 {
		// 1A. Primary correlation: check if PID matches container HostPID (e.g. host networking or direct container PID)
		if container, mapping, err := c.CorrelatePID(ctx, l.PID); err == nil && container != nil {
			container.AttributionMode = domain.AttributionDirect
			for _, p := range container.Ports {
				if p.HostPort == l.Port && matchAddressScore(l.Address, p.HostIP) > 0 {
					if proto == "" || p.Protocol == "" || strings.EqualFold(p.Protocol, proto) {
						pCopy := p
						return container, &pCopy, nil
					}
				}
			}
			return container, mapping, nil
		}

		// 1B. State 2: Process positively verified as docker-proxy
		// docker-proxy is the host process spawned by Docker daemon to forward traffic to the container.
		if strings.EqualFold(l.ProcessName, "docker-proxy") {
			if l.Port > 0 {
				container, mapping, err := c.CorrelatePortProto(ctx, proto, l.Address, l.Port)
				if err != nil {
					return nil, nil, err
				}
				container.AttributionMode = domain.AttributionDirect
				return container, mapping, nil
			}
			return nil, nil, ErrContainerNotFound
		}

		// 1C. State 1 & State 3: Nonzero PID that is NOT docker-proxy and does not match container HostPID.
		// Never allow Docker fallback to override a native process, nor assume an uninspected nonzero PID is Docker.
		return nil, nil, ErrContainerNotFound
	}

	// 2. If PID == 0:
	// State 5: If ProcessName is an identified native process (not empty, not "unknown", not "docker-proxy"), reject.
	if l.ProcessName != "" && !strings.EqualFold(l.ProcessName, "unknown") && !strings.EqualFold(l.ProcessName, "docker-proxy") {
		return nil, nil, ErrContainerNotFound
	}

	// State 4: Unprivileged Linux listener (PID == 0 and ProcessName is "" or "unknown" or "docker-proxy").
	// Sockets owned by root docker-proxy cannot have their PID/FD inspected by unprivileged users.
	// Eligible for Docker published port inference fallback.
	if l.Port > 0 {
		container, mapping, err := c.CorrelatePortProto(ctx, proto, l.Address, l.Port)
		if err != nil {
			return nil, nil, err
		}
		container.AttributionMode = domain.AttributionInferred
		return container, mapping, nil
	}

	return nil, nil, ErrContainerNotFound
}

func extractErrorText(err error) string {
	if err == nil {
		return ""
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return string(exitErr.Stderr) + " " + err.Error()
	}
	return err.Error()
}

func wrapDockerError(err error) error {
	if err == nil {
		return nil
	}
	errStr := strings.ToLower(extractErrorText(err))
	if strings.Contains(errStr, "executable file not found") || strings.Contains(errStr, "not found in $path") || strings.Contains(errStr, "not found in %path%") {
		return ErrDockerNotAvailable
	}
	if strings.Contains(errStr, "permission denied") {
		return ErrDockerPermissionDenied
	}
	if strings.Contains(errStr, "no such file or directory") {
		return ErrDockerSocketMissing
	}
	if strings.Contains(errStr, "is the docker daemon running") || strings.Contains(errStr, "cannot connect to the docker daemon") || strings.Contains(errStr, "connection refused") {
		return ErrDaemonStopped
	}
	if strings.Contains(errStr, "daemon") || strings.Contains(errStr, "connect") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return ErrDaemonNotAvailable
	}
	return fmt.Errorf("docker command failed: %w", err)
}
