package docker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"lantern/internal/domain"
)

// CommandRunner defines the function signature for executing CLI commands.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// CLIClient implements DockerCorrelator using the system `docker` CLI.
type CLIClient struct {
	runner CommandRunner
}

// NewCLIClient creates a new CLIClient with the default exec runner.
func NewCLIClient() *CLIClient {
	return NewCLIClientWithRunner(defaultCommandRunner)
}

// NewCLIClientWithRunner allows injecting a custom CommandRunner for deterministic testing.
func NewCLIClientWithRunner(runner CommandRunner) *CLIClient {
	return &CLIClient{runner: runner}
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// IsAvailable checks whether the docker CLI is present and the daemon is responsive.
func (c *CLIClient) IsAvailable(ctx context.Context) bool {
	_, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	_, err = c.runner(ctx, "docker", "ps", "-q")
	return err == nil
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

// matchAddressScore scores compatibility between listener address and Docker published host IP.
// 2 = exact match, 1 = wildcard match, 0 = no match.
func matchAddressScore(listenerAddr, mappingIP string) int {
	listenerAddr = strings.TrimSpace(listenerAddr)
	mappingIP = strings.TrimSpace(mappingIP)

	if listenerAddr == "" {
		listenerAddr = "0.0.0.0"
	}
	if mappingIP == "" {
		mappingIP = "0.0.0.0"
	}

	// Exact host-IP match is valid
	if listenerAddr == mappingIP {
		return 2
	}

	// Docker wildcard host binding (0.0.0.0 or ::) may match an appropriate listener address
	if mappingIP == "0.0.0.0" || mappingIP == "::" {
		return 1
	}

	// If listener is wildcard and mapping is wildcard
	if (listenerAddr == "0.0.0.0" || listenerAddr == "::") && (mappingIP == "0.0.0.0" || mappingIP == "::") {
		return 1
	}

	// Unrelated specific host IPs must not match (e.g. 127.0.0.1 vs 192.168.1.50)
	return 0
}

// CorrelatePort finds a container that published the specified host address and port.
// Returns ErrAmbiguousMapping if multiple containers match the same listener address and port.
func (c *CLIClient) CorrelatePort(ctx context.Context, address string, port uint16) (*domain.Container, *domain.PortMapping, error) {
	if port == 0 {
		return nil, nil, ErrContainerNotFound
	}

	containers, err := c.ListContainers(ctx)
	if err != nil {
		return nil, nil, err
	}

	var candidates []candidateMatch
	for _, container := range containers {
		for _, p := range container.Ports {
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

// CorrelateListener correlates a listener with a container using PID first, then published port/address fallback.
func (c *CLIClient) CorrelateListener(ctx context.Context, l domain.Listener) (*domain.Container, *domain.PortMapping, error) {
	// 1. Primary correlation: listener PID -> Docker container Host PID
	if l.PID > 0 {
		if container, mapping, err := c.CorrelatePID(ctx, l.PID); err == nil && container != nil {
			// If container has a port mapping matching the listener port and address, return that specific mapping
			for _, p := range container.Ports {
				if p.HostPort == l.Port && matchAddressScore(l.Address, p.HostIP) > 0 {
					pCopy := p
					return container, &pCopy, nil
				}
			}
			return container, mapping, nil
		}
	}

	// 2. Secondary correlation: port/address fallback ONLY for docker-proxy.
	// Port-based fallback must NOT run for arbitrary native processes (e.g. python, node, nginx).
	if l.ProcessName != "docker-proxy" {
		return nil, nil, ErrContainerNotFound
	}

	if l.Port > 0 {
		return c.CorrelatePort(ctx, l.Address, l.Port)
	}

	return nil, nil, ErrContainerNotFound
}

func wrapDockerError(err error) error {
	if err == nil {
		return nil
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "not found") || strings.Contains(errStr, "executable file not found") {
		return ErrDockerNotAvailable
	}
	if strings.Contains(errStr, "daemon") || strings.Contains(errStr, "connect") || strings.Contains(errStr, "permission denied") {
		return ErrDaemonNotAvailable
	}
	return fmt.Errorf("docker command failed: %w", err)
}
