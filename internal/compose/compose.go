package compose

import (
	"context"
	"lantern/internal/domain"
)

// ComposeResolver defines the interface for attributing port mappings to Compose configuration files.
type ComposeResolver interface {
	ResolveAttribution(ctx context.Context, container *domain.Container, hostPort uint16) (*domain.ConfigEvidence, error)
}
