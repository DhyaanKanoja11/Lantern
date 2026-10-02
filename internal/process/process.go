package process

import (
	"context"
	"lantern/internal/domain"
)

// ProcessInspector defines the interface for discovering process metadata by PID.
type ProcessInspector interface {
	Inspect(ctx context.Context, pid int) (*domain.Process, error)
	Correlate(ctx context.Context, pid int) (*domain.Process, error)
}

// ProcessCorrelator is an alias for ProcessInspector for backwards compatibility.
type ProcessCorrelator = ProcessInspector

// NewDefaultInspector returns the platform-appropriate process inspector.
func NewDefaultInspector() ProcessInspector {
	return newPlatformInspector()
}
