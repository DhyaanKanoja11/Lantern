package network

import (
	"context"
	"lantern/internal/domain"
)

// InterfaceClassifier defines the interface for discovering and classifying host network interfaces.
type InterfaceClassifier interface {
	DiscoverInterfaces(ctx context.Context) ([]domain.NetworkInterface, error)
	ClassifyReachability(bindAddr string, ifaces []domain.NetworkInterface) domain.Reachability
	Assess(ctx context.Context, bindAddr string) (domain.Reachability, []domain.NetworkInterface, error)
}
