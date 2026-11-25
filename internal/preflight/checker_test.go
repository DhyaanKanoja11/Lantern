package preflight

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

type mockCollector struct {
	listeners []domain.Listener
	err       error
}

func (m *mockCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	return m.listeners, m.err
}

func (m *mockCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
	for _, l := range m.listeners {
		if l.Port == port {
			return &l, nil
		}
	}
	return nil, nil
}

type mockInspector struct {
	proc *domain.Process
	err  error
}

func (m *mockInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	return m.proc, m.err
}

func (m *mockInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return m.Inspect(ctx, pid)
}

func TestChecker_CleanPass(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), composePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected report to pass, but failed with %d collisions", len(report.Collisions))
	}
	if len(report.Wildcards) != 0 {
		t.Errorf("expected 0 wildcards, got %d", len(report.Wildcards))
	}
}

func TestChecker_HostCollision(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `
services:
  db:
    image: postgres
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{
				Address: "0.0.0.0",
				Port:    5432,
				PID:     1234,
			},
		},
	}
	mockInsp := &mockInspector{
		proc: &domain.Process{
			PID:  1234,
			Name: "postgres",
		},
	}

	checker := NewCheckerWithDeps(mockCol, mockInsp)
	report, err := checker.CheckFile(context.Background(), composePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Passed {
		t.Error("expected report to fail on host collision, but it passed")
	}
	if len(report.Collisions) != 1 {
		t.Fatalf("expected 1 collision, got %d", len(report.Collisions))
	}

	col := report.Collisions[0]
	if col.Port != 5432 || col.Kind != "HOST_COLLISION" {
		t.Errorf("unexpected collision: %+v", col)
	}
	if col.OccupiedBy != "postgres (PID 1234)" {
		t.Errorf("expected occupant 'postgres (PID 1234)', got: %s", col.OccupiedBy)
	}
	if col.SuggestedPort == 0 {
		t.Error("expected suggested port to be > 0")
	}

	// Also verify wildcard detection
	if len(report.Wildcards) != 1 {
		t.Errorf("expected 1 wildcard exposure detected, got %d", len(report.Wildcards))
	}
}

func TestChecker_InternalDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `
services:
  app1:
    image: node
    ports:
      - "127.0.0.1:3000:3000"
  app2:
    image: node
    ports:
      - "127.0.0.1:3000:4000"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), composePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Passed {
		t.Error("expected internal duplicate to fail")
	}
	if len(report.Collisions) != 1 {
		t.Fatalf("expected 1 collision, got %d", len(report.Collisions))
	}

	col := report.Collisions[0]
	if col.Kind != "INTERNAL_DUPLICATE" || col.Port != 3000 {
		t.Errorf("unexpected collision: %+v", col)
	}
}

func TestChecker_NonExistentFile(t *testing.T) {
	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	_, err := checker.CheckFile(context.Background(), "non_existent_file.yml")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}
