package docker

import (
	"context"
	"errors"

	"lantern/internal/domain"
)

var (
	// ErrDockerNotAvailable indicates the docker executable is not installed on PATH.
	ErrDockerNotAvailable = errors.New("docker CLI is not available in PATH")
	// ErrDaemonNotAvailable indicates the Docker daemon is stopped, unreachable, or permission is denied.
	ErrDaemonNotAvailable = errors.New("docker daemon is not accessible")
	// ErrContainerNotFound indicates no matching container was discovered.
	ErrContainerNotFound = errors.New("container not found")
	// ErrAmbiguousMapping indicates multiple containers legitimately match the same listener address and port.
	ErrAmbiguousMapping = errors.New("ambiguous container mapping: multiple containers match listener")
)

// Client defines the interface for Docker container discovery.
type Client interface {
	ListContainers(ctx context.Context) ([]domain.Container, error)
	InspectContainer(ctx context.Context, id string) (*domain.Container, error)
}

// DockerCorrelator correlates listeners and processes with Docker containers.
type DockerCorrelator interface {
	Client
	IsAvailable(ctx context.Context) bool
	CorrelatePID(ctx context.Context, pid int) (*domain.Container, *domain.PortMapping, error)
	CorrelatePort(ctx context.Context, address string, port uint16) (*domain.Container, *domain.PortMapping, error)
	CorrelateListener(ctx context.Context, l domain.Listener) (*domain.Container, *domain.PortMapping, error)
}

// NewDefaultCorrelator returns a DockerCorrelator using the system Docker CLI.
func NewDefaultCorrelator() DockerCorrelator {
	return NewCLIClient()
}
