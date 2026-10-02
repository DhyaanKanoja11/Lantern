package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lantern/internal/domain"
	"lantern/internal/remediation"
)

type mockFixAnalyzer struct {
	exposure *domain.Exposure
	err      error
}

func (m *mockFixAnalyzer) Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.exposure, nil
}

func (m *mockFixAnalyzer) Scan(ctx context.Context) ([]domain.ExposureSummary, error) {
	return nil, nil
}

func TestFixCommand_InvalidPort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "abc"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-numeric port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port number") {
		t.Errorf("expected invalid port number error, got: %v", err)
	}
}

func TestFixCommand_OutOfRangePort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "99999"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for out of range port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port number") {
		t.Errorf("expected out of range port error, got: %v", err)
	}
}

func TestFixCommand_ZeroPort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "0"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for port 0, got nil")
	}
}

func TestFixCommand_MissingArg(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when port argument is omitted, got nil")
	}
}

func TestFixCommand_UnsupportedExposure(t *testing.T) {
	oldAnalyzer := fixAnalyzer
	defer func() { fixAnalyzer = oldAnalyzer }()

	// Native process exposure -> unsupported
	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        3000,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     3000,
				Protocol: "tcp",
				Address:  "0.0.0.0",
			},
			Process: &domain.Process{
				PID:  1234,
				Name: "node",
			},
			Reachability: domain.Reachability{
				Local: true,
				LAN:   "yes",
				State: "LAN_REACHABLE",
			},
		},
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"fix", "3000"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected command error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Automatic remediation is not supported for this exposure type.") {
		t.Errorf("expected unsupported message, got:\n%s", out)
	}
	if !strings.Contains(out, "native process") {
		t.Errorf("expected native process explanation, got:\n%s", out)
	}
}

func TestFixCommand_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	oldAnalyzer := fixAnalyzer
	oldRemediator := fixRemediator
	defer func() {
		fixAnalyzer = oldAnalyzer
		fixRemediator = oldRemediator
		dryRunFlag = false
	}()

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
			},
			Container: &domain.Container{
				ID:   "c1",
				Name: "postgres",
			},
			DockerMapping: &domain.PortMapping{
				HostIP:        "0.0.0.0",
				HostPort:      5432,
				ContainerPort: 5432,
				Protocol:      "tcp",
			},
			Config: &domain.ConfigEvidence{
				File:          composePath,
				Line:          5,
				Evidence:      "5432:5432",
				Service:       "db",
				HostPort:      5432,
				ContainerPort: 5432,
				Certain:       true,
			},
			Recommendation: &domain.Recommendation{
				Type:      "bind_localhost",
				Current:   "5432:5432",
				Suggested: "127.0.0.1:5432:5432",
			},
			Reachability: domain.Reachability{
				Local: true,
				LAN:   "yes",
				State: "LAN_REACHABLE",
			},
		},
	}
	fixRemediator = remediation.NewDefaultRemediator()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"fix", "5432", "--dry-run"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error during dry-run: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Dry-run mode: no changes will be made.") {
		t.Errorf("expected dry-run banner, got:\n%s", out)
	}
	if !strings.Contains(out, "Proposed:\n    127.0.0.1:5432:5432") {
		t.Errorf("expected proposed modification in dry-run, got:\n%s", out)
	}
	if !strings.Contains(out, composePath+".lantern.bak") {
		t.Errorf("expected predicted backup path, got:\n%s", out)
	}

	// Verify ZERO writes occurred
	afterContent, _ := os.ReadFile(composePath)
	if string(afterContent) != composeContent {
		t.Errorf("dry-run modified file content on disk:\n%s", string(afterContent))
	}
	if _, err := os.Stat(composePath + ".lantern.bak"); !os.IsNotExist(err) {
		t.Errorf("dry-run created a backup file on disk")
	}
}

func TestFixCommand_Confirmation_No(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	oldAnalyzer := fixAnalyzer
	oldRemediator := fixRemediator
	defer func() {
		fixAnalyzer = oldAnalyzer
		fixRemediator = oldRemediator
		dryRunFlag = false
	}()

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
			},
			Container: &domain.Container{
				ID:   "c1",
				Name: "postgres",
			},
			DockerMapping: &domain.PortMapping{
				HostIP:        "0.0.0.0",
				HostPort:      5432,
				ContainerPort: 5432,
				Protocol:      "tcp",
			},
			Config: &domain.ConfigEvidence{
				File:          composePath,
				Line:          5,
				Evidence:      "5432:5432",
				Service:       "db",
				HostPort:      5432,
				ContainerPort: 5432,
				Certain:       true,
			},
			Recommendation: &domain.Recommendation{
				Type:      "bind_localhost",
				Current:   "5432:5432",
				Suggested: "127.0.0.1:5432:5432",
			},
			Reachability: domain.Reachability{
				Local: true,
				LAN:   "yes",
				State: "LAN_REACHABLE",
			},
		},
	}
	fixRemediator = remediation.NewDefaultRemediator()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	// Simulate user typing "n" or pressing Enter (empty input defaults to No)
	rootCmd.SetIn(strings.NewReader("n\n"))
	rootCmd.SetArgs([]string{"fix", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Operation cancelled. No changes made.") {
		t.Errorf("expected cancellation message, got:\n%s", out)
	}

	// Verify ZERO writes occurred
	afterContent, _ := os.ReadFile(composePath)
	if string(afterContent) != composeContent {
		t.Errorf("cancelled operation modified file content on disk:\n%s", string(afterContent))
	}
}

func TestFixCommand_Confirmation_Yes(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	oldAnalyzer := fixAnalyzer
	oldRemediator := fixRemediator
	defer func() {
		fixAnalyzer = oldAnalyzer
		fixRemediator = oldRemediator
		dryRunFlag = false
	}()

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
			},
			Container: &domain.Container{
				ID:   "c1",
				Name: "postgres",
			},
			DockerMapping: &domain.PortMapping{
				HostIP:        "0.0.0.0",
				HostPort:      5432,
				ContainerPort: 5432,
				Protocol:      "tcp",
			},
			Config: &domain.ConfigEvidence{
				File:          composePath,
				Line:          5,
				Evidence:      "5432:5432",
				Service:       "db",
				HostPort:      5432,
				ContainerPort: 5432,
				Certain:       true,
			},
			Recommendation: &domain.Recommendation{
				Type:      "bind_localhost",
				Current:   "5432:5432",
				Suggested: "127.0.0.1:5432:5432",
			},
			Reachability: domain.Reachability{
				Local: true,
				LAN:   "yes",
				State: "LAN_REACHABLE",
			},
		},
	}
	fixRemediator = remediation.NewDefaultRemediator()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	// Simulate user typing "y"
	rootCmd.SetIn(strings.NewReader("y\n"))
	rootCmd.SetArgs([]string{"fix", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Fix applied successfully.") {
		t.Errorf("expected success message, got:\n%s", out)
	}
	if !strings.Contains(out, "Before:") || !strings.Contains(out, "After:") {
		t.Errorf("expected before/after breakdown, got:\n%s", out)
	}
	if !strings.Contains(out, "Backup:") {
		t.Errorf("expected backup location reported, got:\n%s", out)
	}

	// Verify file modified on disk
	afterContent, _ := os.ReadFile(composePath)
	if !strings.Contains(string(afterContent), `"127.0.0.1:5432:5432"`) {
		t.Errorf("expected file on disk to contain 127.0.0.1:5432:5432, got:\n%s", string(afterContent))
	}

	// Verify backup file exists on disk
	bakPath := composePath + ".lantern.bak"
	if _, err := os.Stat(bakPath); err != nil {
		t.Errorf("expected backup file %s to exist: %v", bakPath, err)
	}
}

type toctouModifyingRemediator struct {
	underlying   remediation.Remediator
	fileToModify string
	newContent   string
}

func (m *toctouModifyingRemediator) Plan(ctx context.Context, exp *domain.Exposure) (*domain.Remediation, error) {
	return m.underlying.Plan(ctx, exp)
}

func (m *toctouModifyingRemediator) Apply(ctx context.Context, plan *domain.Remediation) (*domain.FixResult, error) {
	// Simulate external modification to file right before Apply executes
	_ = os.WriteFile(m.fileToModify, []byte(m.newContent), 0644)
	return m.underlying.Apply(ctx, plan)
}

func TestFixCommand_TOCTOU_AbortsCleanly(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := "services:\n  db:\n    ports:\n      - \"5432:5432\"\n"
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	oldAnalyzer := fixAnalyzer
	oldRemediator := fixRemediator
	defer func() {
		fixAnalyzer = oldAnalyzer
		fixRemediator = oldRemediator
		dryRunFlag = false
	}()

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
			},
			Container: &domain.Container{
				ID:   "c1",
				Name: "postgres",
			},
			DockerMapping: &domain.PortMapping{
				HostIP:        "0.0.0.0",
				HostPort:      5432,
				ContainerPort: 5432,
				Protocol:      "tcp",
			},
			Config: &domain.ConfigEvidence{
				File:          composePath,
				Line:          4,
				Evidence:      "5432:5432",
				Service:       "db",
				HostPort:      5432,
				ContainerPort: 5432,
				Certain:       true,
			},
			Recommendation: &domain.Recommendation{
				Type:      "bind_localhost",
				Current:   "5432:5432",
				Suggested: "127.0.0.1:5432:5432",
			},
			Reachability: domain.Reachability{
				Local: true,
				LAN:   "yes",
				State: "LAN_REACHABLE",
			},
		},
	}

	externalModifiedContent := "services:\n  db:\n    ports:\n      - \"5432:5432\"\n    restart: always\n"
	fixRemediator = &toctouModifyingRemediator{
		underlying:   remediation.NewDefaultRemediator(),
		fileToModify: composePath,
		newContent:   externalModifiedContent,
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetIn(strings.NewReader("y\n"))
	rootCmd.SetArgs([]string{"fix", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected clean exit on TOCTOU failure, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "The configuration file changed after analysis.") {
		t.Errorf("expected TOCTOU notification, got:\n%s", out)
	}
	if !strings.Contains(out, "Lantern will not apply the planned change.") {
		t.Errorf("expected non-application guarantee, got:\n%s", out)
	}
	if !strings.Contains(out, "lantern fix 5432") {
		t.Errorf("expected rerun suggestion, got:\n%s", out)
	}

	// Verify the externally modified file was preserved without overwrite
	currentDisk, _ := os.ReadFile(composePath)
	if string(currentDisk) != externalModifiedContent {
		t.Errorf("externally modified file was overwritten, got:\n%s", string(currentDisk))
	}

	// Verify no backup was created
	bakPath := composePath + ".lantern.bak"
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Errorf("expected no backup to be created on TOCTOU failure")
	}
}
