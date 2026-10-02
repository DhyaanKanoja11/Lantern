package network

import (
	"context"
	"errors"
	"testing"

	"lantern/internal/domain"
)

type mockProvider struct {
	ifaces []domain.NetworkInterface
	err    error
}

func (m *mockProvider) Interfaces(ctx context.Context) ([]domain.NetworkInterface, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ifaces, nil
}

func TestClassifier_Assess_Success(t *testing.T) {
	mock := &mockProvider{
		ifaces: []domain.NetworkInterface{
			{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
			{Name: "eth0", IP: "192.168.1.100", Kind: "LAN", IsLoopback: false, IsUp: true},
		},
	}

	classifier := NewClassifierWithProvider(mock)

	reach, relevant, err := classifier.Assess(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reach.State != StateLoopbackOnly {
		t.Errorf("expected %s, got %s", StateLoopbackOnly, reach.State)
	}
	if len(relevant) != 1 || relevant[0].Name != "lo" {
		t.Errorf("expected relevant lo interface, got %+v", relevant)
	}
}

func TestClassifier_Assess_ProviderFailure(t *testing.T) {
	mock := &mockProvider{
		err: errors.New("simulated network interface enumeration failure"),
	}

	classifier := NewClassifierWithProvider(mock)

	reach, relevant, err := classifier.Assess(context.Background(), "0.0.0.0")
	if err == nil {
		t.Fatalf("expected error from failed provider, got nil")
	}
	if reach.State != StateUnresolved {
		t.Errorf("expected StateUnresolved on provider failure, got %s", reach.State)
	}
	if len(relevant) != 0 {
		t.Errorf("expected 0 relevant interfaces on error, got %d", len(relevant))
	}
}

func TestClassifier_Assess_EmptyInterfaces(t *testing.T) {
	mock := &mockProvider{
		ifaces: nil,
	}

	classifier := NewClassifierWithProvider(mock)

	reach, relevant, err := classifier.Assess(context.Background(), "0.0.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reach.State != StateUnresolved {
		t.Errorf("expected StateUnresolved when no interfaces exist, got %s", reach.State)
	}
	if len(relevant) != 0 {
		t.Errorf("expected 0 relevant interfaces, got %d", len(relevant))
	}
}
