package collector

import (
	"context"
	"lantern/internal/domain"
)

// ListenerCollector defines the interface for discovering active listening sockets.
type ListenerCollector interface {
	CollectListeners(ctx context.Context) ([]domain.Listener, error)
	FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error)
}

// NewDefaultCollector returns the platform-appropriate listener collector.
func NewDefaultCollector() ListenerCollector {
	return newPlatformCollector()
}
