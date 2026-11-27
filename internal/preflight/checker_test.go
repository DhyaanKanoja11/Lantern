package preflight

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/compose"
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

func TestChecker_AutoDiscoversOverrideFile(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "docker-compose.yml")
	overridePath := filepath.Join(tmpDir, "docker-compose.override.yml")

	baseContent := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	overrideContent := `
services:
  api:
    image: node
    ports:
      - "3000:3000"
`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte(overrideContent), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Files) != 2 || report.Files[0] != basePath || report.Files[1] != overridePath {
		t.Errorf("expected both base and override files in report.Files, got: %v", report.Files)
	}
	if report.TotalPorts != 2 {
		t.Errorf("expected 2 merged ports, got %d", report.TotalPorts)
	}
	if !report.Passed {
		t.Errorf("expected merged report to pass, got collisions: %+v", report.Collisions)
	}
	if len(report.Wildcards) != 1 || report.Wildcards[0].Service != "api" || report.Wildcards[0].File != overridePath {
		t.Errorf("expected 1 wildcard from override file for service api, got: %+v", report.Wildcards)
	}
}

func TestChecker_OverrideCollisionAcrossFiles(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "docker-compose.yml")
	overridePath := filepath.Join(tmpDir, "docker-compose.override.yml")

	baseContent := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	overrideContent := `
services:
  admin:
    image: caddy
    ports:
      - "127.0.0.1:8080:8080"
`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte(overrideContent), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Passed {
		t.Fatal("expected collision across base and override files to fail")
	}
	if len(report.Collisions) != 1 {
		t.Fatalf("expected 1 collision, got %d", len(report.Collisions))
	}

	col := report.Collisions[0]
	if col.Kind != "INTERNAL_DUPLICATE" || col.Port != 8080 || col.Service != "admin" {
		t.Errorf("unexpected collision details: %+v", col)
	}
	if !strings.Contains(col.OccupiedBy, "docker-compose.yml") {
		t.Errorf("expected OccupiedBy to reference docker-compose.yml, got: %s", col.OccupiedBy)
	}
}

func TestChecker_OverrideDeduplicatesIdenticalServicePort(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "docker-compose.yml")
	overridePath := filepath.Join(tmpDir, "docker-compose.override.yml")

	content := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(basePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), basePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !report.Passed {
		t.Errorf("expected identical port declaration for same service to deduplicate without collision, got: %+v", report.Collisions)
	}
	if report.TotalPorts != 1 {
		t.Errorf("expected 1 deduplicated port, got %d", report.TotalPorts)
	}
}

func TestChecker_CheckFilesExplicitMultiple(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "compose.yaml")
	stagingPath := filepath.Join(tmpDir, "compose.staging.yaml")

	baseContent := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	stagingContent := `
services:
  db:
    image: postgres
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagingPath, []byte(stagingContent), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{Address: "127.0.0.1", Port: 5432, PID: 999},
		},
	}

	checker := NewCheckerWithDeps(mockCol, nil)
	report, err := checker.CheckFiles(context.Background(), basePath, stagingPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Passed {
		t.Fatal("expected host collision on 5432 from staging file to fail")
	}
	if len(report.Collisions) != 1 || report.Collisions[0].File != stagingPath {
		t.Errorf("expected collision attributed to %s, got: %+v", stagingPath, report.Collisions)
	}
	if len(report.Wildcards) != 1 || report.Wildcards[0].Port != 5432 {
		t.Errorf("expected wildcard on 5432, got: %+v", report.Wildcards)
	}
}

func TestChecker_Reallocate_SingleCollision(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "compose.yaml")
	content := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{Address: "0.0.0.0", Port: 8080, PID: 1234},
		},
	}
	checker := NewCheckerWithDeps(mockCol, nil)
	report, err := checker.CheckFile(context.Background(), filePath)
	if err != nil {
		t.Fatalf("CheckFile failed: %v", err)
	}
	if len(report.Collisions) != 1 {
		t.Fatalf("expected 1 collision, got %d", len(report.Collisions))
	}

	outcome, err := checker.Reallocate(context.Background(), report, false)
	if err != nil {
		t.Fatalf("Reallocate failed: %v", err)
	}
	if len(outcome.Reallocations) != 1 {
		t.Fatalf("expected 1 reallocation, got %d", len(outcome.Reallocations))
	}
	r := outcome.Reallocations[0]
	if r.OldPort != 8080 || r.NewPort == 8080 || r.NewPort == 0 {
		t.Errorf("unexpected reallocation: %+v", r)
	}

	// Verify backup
	backupPath := outcome.Backups[filePath]
	if backupPath == "" {
		t.Fatal("expected backup path for compose file")
	}
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	if !bytes.Equal(backupData, []byte(content)) {
		t.Errorf("backup bytes mismatch original bytes")
	}

	// Verify modified content on disk
	diskData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read modified file: %v", err)
	}
	expectedSub := fmt.Sprintf(`"%d:80"`, r.NewPort)
	if !strings.Contains(string(diskData), expectedSub) {
		t.Errorf("expected disk data to contain %s, got:\n%s", expectedSub, string(diskData))
	}
}

func TestChecker_Reallocate_TwoServicesCollide_DistinctPorts(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "compose.yaml")
	content := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
  api:
    image: node
    ports:
      - "8080:3000"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	report, err := checker.CheckFile(context.Background(), filePath)
	if err != nil {
		t.Fatalf("CheckFile failed: %v", err)
	}
	if len(report.Collisions) == 0 {
		t.Fatal("expected collision between web and api on 8080")
	}

	outcome, err := checker.Reallocate(context.Background(), report, false)
	if err != nil {
		t.Fatalf("Reallocate failed: %v", err)
	}
	for _, r := range outcome.Reallocations {
		if r.NewPort == 8080 {
			t.Errorf("reallocated to same colliding port 8080")
		}
	}

	// Verify modified disk data parses cleanly
	diskData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read disk file: %v", err)
	}
	if _, err := compose.ParseComposeFile(filePath, diskData); err != nil {
		t.Fatalf("modified compose failed parsing: %v", err)
	}
}

func TestChecker_Reallocate_TwoExternalCollisions_DistinctPorts(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "compose.yaml")
	content := `services:
  web1:
    image: nginx
    ports:
      - "8080:80"
  web2:
    image: nginx
    ports:
      - "8081:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{Address: "0.0.0.0", Port: 8080, PID: 100},
			{Address: "0.0.0.0", Port: 8081, PID: 101},
		},
	}
	checker := NewCheckerWithDeps(mockCol, nil)
	report, err := checker.CheckFile(context.Background(), filePath)
	if err != nil {
		t.Fatalf("CheckFile failed: %v", err)
	}
	if len(report.Collisions) != 2 {
		t.Fatalf("expected 2 collisions, got %d", len(report.Collisions))
	}

	outcome, err := checker.Reallocate(context.Background(), report, false)
	if err != nil {
		t.Fatalf("Reallocate failed: %v", err)
	}
	if len(outcome.Reallocations) != 2 {
		t.Fatalf("expected 2 reallocations, got %d", len(outcome.Reallocations))
	}
	p1 := outcome.Reallocations[0].NewPort
	p2 := outcome.Reallocations[1].NewPort
	if p1 == p2 {
		t.Errorf("expected distinct ports for colliding services, but both got %d", p1)
	}
	if p1 == 8080 || p1 == 8081 || p2 == 8080 || p2 == 8081 {
		t.Errorf("expected neither port to match existing occupied ports (8080, 8081), got %d and %d", p1, p2)
	}
}

func TestChecker_Reallocate_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "compose.yaml")
	content := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{Address: "0.0.0.0", Port: 8080, PID: 100},
		},
	}
	checker := NewCheckerWithDeps(mockCol, nil)
	report, err := checker.CheckFile(context.Background(), filePath)
	if err != nil {
		t.Fatalf("CheckFile failed: %v", err)
	}

	outcome, err := checker.Reallocate(context.Background(), report, true)
	if err != nil {
		t.Fatalf("Reallocate dry-run failed: %v", err)
	}
	if len(outcome.Reallocations) != 1 {
		t.Fatalf("expected 1 reallocation, got %d", len(outcome.Reallocations))
	}
	if len(outcome.Backups) != 0 {
		t.Errorf("expected no backups on dry-run, got: %+v", outcome.Backups)
	}
	if !strings.Contains(outcome.Diff, "--- a/compose.yaml") || !strings.Contains(outcome.Diff, "+++ b/compose.yaml") {
		t.Errorf("expected unified diff format, got:\n%s", outcome.Diff)
	}

	// Verify disk file was not modified
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte(content)) {
		t.Errorf("expected file on disk to remain unchanged on dry-run")
	}

	// Verify no backup was created
	bakFile := filePath + ".lantern.bak"
	if _, err := os.Stat(bakFile); !os.IsNotExist(err) {
		t.Errorf("expected no backup file on disk on dry-run")
	}
}

func TestChecker_Reallocate_FailClosed_InterpolatedAndRange(t *testing.T) {
	tmpDir := t.TempDir()
	interpFile := filepath.Join(tmpDir, "interp.yaml")
	interpContent := `services:
  web:
    image: nginx
    ports:
      - "${PORT}:80"
`
	if err := os.WriteFile(interpFile, []byte(interpContent), 0644); err != nil {
		t.Fatal(err)
	}

	mockCol := &mockCollector{
		listeners: []domain.Listener{
			{Address: "0.0.0.0", Port: 8080, PID: 100},
		},
	}
	checker := NewCheckerWithDeps(mockCol, nil)
	reportInterp := &Report{
		FilePath: interpFile,
		Collisions: []Collision{
			{Port: 8080, Service: "web", Line: 5, File: interpFile},
		},
	}
	_, err := checker.Reallocate(context.Background(), reportInterp, false)
	if err == nil {
		t.Fatal("expected failure on interpolated port, got nil")
	}
	if !strings.Contains(err.Error(), "variable interpolation") {
		t.Errorf("expected variable interpolation error, got: %v", err)
	}

	// Range file
	rangeFile := filepath.Join(tmpDir, "range.yaml")
	rangeContent := `services:
  web:
    image: nginx
    ports:
      - "8080-8085:80-85"
`
	if err := os.WriteFile(rangeFile, []byte(rangeContent), 0644); err != nil {
		t.Fatal(err)
	}
	reportRange := &Report{
		FilePath: rangeFile,
		Collisions: []Collision{
			{Port: 8080, Service: "web", Line: 5, File: rangeFile},
		},
	}
	_, err = checker.Reallocate(context.Background(), reportRange, false)
	if err == nil {
		t.Fatal("expected failure on port range, got nil")
	}
	if !strings.Contains(err.Error(), "port ranges are not supported") {
		t.Errorf("expected port range error, got: %v", err)
	}
}

func TestChecker_Reallocate_NoCollision(t *testing.T) {
	report := &Report{
		FilePath:   "compose.yaml",
		Collisions: []Collision{},
		Passed:     true,
	}
	checker := NewCheckerWithDeps(&mockCollector{}, nil)
	outcome, err := checker.Reallocate(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(outcome.Reallocations) != 0 {
		t.Errorf("expected 0 reallocations, got %d", len(outcome.Reallocations))
	}
}
