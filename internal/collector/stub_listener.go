//go:build !linux

package collector

import (
	"context"
	"fmt"
	"lantern/internal/domain"
)

type stubCollector struct{}

func newPlatformCollector() ListenerCollector {
	return &stubCollector{}
}

func (s *stubCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	return nil, fmt.Errorf("listener discovery is currently only supported on Linux / WSL2")
}

func (s *stubCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
	return nil, fmt.Errorf("listener discovery is currently only supported on Linux / WSL2")
}
