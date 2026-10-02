package docker

import (
	"context"
	"lantern/internal/domain"
)

// DockerCorrelator defines the interface for correlating host ports to Docker containers.
type DockerCorrelator interface {
	IsAvailable(ctx context.Context) bool
	CorrelatePort(ctx context.Context, port uint16) (*domain.Container, *domain.PortMapping, error)
	ListContainers(ctx context.Context) ([]domain.Container, error)
}
