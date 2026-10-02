package process

import (
	"context"
	"lantern/internal/domain"
)

// ProcessCorrelator defines the interface for discovering process metadata by PID.
type ProcessCorrelator interface {
	Correlate(ctx context.Context, pid int) (*domain.Process, error)
}
