//go:build !linux

package process

import (
	"context"
	"fmt"
	"lantern/internal/domain"
)

type stubInspector struct{}

func newPlatformInspector() ProcessInspector {
	return &stubInspector{}
}

func (s *stubInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	return nil, fmt.Errorf("process inspection is currently only supported on Linux / WSL2")
}

func (s *stubInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return s.Inspect(ctx, pid)
}
