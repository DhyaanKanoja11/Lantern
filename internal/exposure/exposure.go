package exposure

import (
	"context"
	"lantern/internal/domain"
)

// Analyzer defines the core engine interface for analyzing service reachability.
type Analyzer interface {
	Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error)
	Scan(ctx context.Context) ([]domain.ExposureSummary, error)
}
