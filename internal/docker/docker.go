package docker

import (
	"context"
	"errors"
	"fmt"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

var (
	// ErrDockerNotAvailable indicates the docker executable is not installed on PATH.
	ErrDockerNotAvailable = errors.New("docker CLI is not available in PATH")
	// ErrDaemonNotAvailable indicates the Docker daemon is stopped, unreachable, or permission is denied.
	ErrDaemonNotAvailable = errors.New("docker daemon is not accessible")
	// ErrDaemonStopped indicates the Docker daemon service is not running.
	ErrDaemonStopped = fmt.Errorf("%w: daemon is not running", ErrDaemonNotAvailable)
	// ErrDockerSocketMissing indicates the Docker socket file was not found.
	ErrDockerSocketMissing = fmt.Errorf("%w: socket file not found", ErrDaemonNotAvailable)
	// ErrDockerPermissionDenied indicates permission was denied connecting to the Docker socket.
	ErrDockerPermissionDenied = fmt.Errorf("%w: connection permission denied", ErrDaemonNotAvailable)
	// ErrContainerNotFound indicates no matching container was discovered.
	ErrContainerNotFound = errors.New("container not found")
	// ErrAmbiguousMapping indicates multiple containers legitimately match the same listener address and port.
	ErrAmbiguousMapping = errors.New("ambiguous container mapping: multiple containers match listener")
)

// Client defines the interface for Docker container discovery and lifecycle management.
type Client interface {
	ListContainers(ctx context.Context) ([]domain.Container, error)
	InspectContainer(ctx context.Context, id string) (*domain.Container, error)
	StopContainer(ctx context.Context, id string, timeoutSeconds int) error
}

// DockerCorrelator correlates listeners and processes with Docker containers.
type DockerCorrelator interface {
	Client
	IsAvailable(ctx context.Context) bool
	CheckDaemon(ctx context.Context) error
	CorrelatePID(ctx context.Context, pid int) (*domain.Container, *domain.PortMapping, error)
	CorrelatePort(ctx context.Context, address string, port uint16) (*domain.Container, *domain.PortMapping, error)
	CorrelateListener(ctx context.Context, l domain.Listener) (*domain.Container, *domain.PortMapping, error)
}

// NewDefaultCorrelator returns a DockerCorrelator using the system Docker CLI.
func NewDefaultCorrelator() DockerCorrelator {
	return NewCLIClient()
}
