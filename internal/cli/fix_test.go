package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/remediation"
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

func (m *mockFixAnalyzer) ScanReport(ctx context.Context) (*domain.ScanReport, error) {
	return &domain.ScanReport{}, nil
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

func (m *toctouModifyingRemediator) Diff(ctx context.Context, plan *domain.Remediation) (string, error) {
	return m.underlying.Diff(ctx, plan)
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

func TestFixCommand_InferredAttribution_BlocksLiveFix(t *testing.T) {
	origAnalyzer := fixAnalyzer
	origRemediator := fixRemediator
	defer func() {
		fixAnalyzer = origAnalyzer
		fixRemediator = origRemediator
	}()

	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := "services:\n  db:\n    image: postgres:15\n    ports:\n      - \"5432:5432\"\n"
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
				PID:      0, // unprivileged listener
			},
			Container: &domain.Container{
				ID:              "c_pg",
				Name:            "postgres",
				AttributionMode: domain.AttributionInferred, // Inferred attribution
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
	rootCmd.SetArgs([]string{"fix", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected clean exit when live fix is blocked, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Remediation cannot be safely applied:") {
		t.Errorf("expected unsafe/blocked notification, got:\n%s", out)
	}
	if !strings.Contains(out, "Live remediation is blocked for inferred attribution") {
		t.Errorf("expected live remediation blocked warning, got:\n%s", out)
	}
	if !strings.Contains(out, "--dry-run") {
		t.Errorf("expected dry-run suggestion, got:\n%s", out)
	}

	// Verify file was NOT modified
	diskContent, _ := os.ReadFile(composePath)
	if string(diskContent) != composeContent {
		t.Errorf("file should not have been modified on blocked live fix")
	}
}

func TestFixCommand_InferredAttribution_DryRunPreview(t *testing.T) {
	origAnalyzer := fixAnalyzer
	origRemediator := fixRemediator
	defer func() {
		fixAnalyzer = origAnalyzer
		fixRemediator = origRemediator
		dryRunFlag = false
	}()

	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := "services:\n  db:\n    image: postgres:15\n    ports:\n      - \"5432:5432\"\n"
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	fixAnalyzer = &mockFixAnalyzer{
		exposure: &domain.Exposure{
			Port:        5432,
			Protocol:    "tcp",
			BindAddress: "0.0.0.0",
			Listener: domain.Listener{
				Port:     5432,
				Protocol: "tcp",
				Address:  "0.0.0.0",
				PID:      0, // unprivileged
			},
			Container: &domain.Container{
				ID:              "c_pg",
				Name:            "postgres",
				AttributionMode: domain.AttributionInferred, // Inferred attribution
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
		t.Fatalf("expected clean exit on dry-run, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[WARN] Tentative Preview (Inferred Attribution)") {
		t.Errorf("expected tentative preview warning, got:\n%s", out)
	}
	if !strings.Contains(out, "Proposed (Tentative):") {
		t.Errorf("expected Proposed (Tentative) header, got:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:5432:5432") {
		t.Errorf("expected proposed fix in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Dry-run mode: strictly read-only, no changes will be made.") {
		t.Errorf("expected read-only dry-run guarantee, got:\n%s", out)
	}

	// Verify file was NOT modified
	diskContent, _ := os.ReadFile(composePath)
	if string(diskContent) != composeContent {
		t.Errorf("file should not have been modified on dry-run")
	}
}

func TestFixCommand_DiffFlag_Supported(t *testing.T) {
	origAnalyzer := fixAnalyzer
	origRemediator := fixRemediator
	defer func() {
		fixAnalyzer = origAnalyzer
		fixRemediator = origRemediator
		diffFlag = false
	}()

	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

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
				ID:              "cont-123",
				Name:            "db_1",
				Image:           "postgres:15",
				AttributionMode: domain.AttributionDirect,
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
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "5432", "--diff"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected clean exit on fix --diff, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "--- a/") || !strings.Contains(out, "+++ b/") {
		t.Fatalf("expected git diff headers, got:\n%s", out)
	}
	if !strings.Contains(out, `-      - "5432:5432"`) {
		t.Errorf("expected removed line in diff, got:\n%s", out)
	}
	if !strings.Contains(out, `+      - "127.0.0.1:5432:5432"`) {
		t.Errorf("expected added line in diff, got:\n%s", out)
	}

	// Verify file was NOT modified on disk
	diskBytes, _ := os.ReadFile(composePath)
	if string(diskBytes) != composeContent {
		t.Errorf("expected file to remain unchanged on disk, but content differed")
	}
}

func TestFixCommand_DiffFlag_UnsupportedExposure(t *testing.T) {
	origAnalyzer := fixAnalyzer
	origRemediator := fixRemediator
	defer func() {
		fixAnalyzer = origAnalyzer
		fixRemediator = origRemediator
		diffFlag = false
	}()

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
	fixRemediator = remediation.NewDefaultRemediator()

	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "3000", "--diff"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error on fix --diff for unsupported exposure, got nil")
	}
	if !strings.Contains(err.Error(), "cannot generate diff for UNSUPPORTED") {
		t.Errorf("expected UNSUPPORTED diff error, got: %v", err)
	}
}

func TestFixCommand_DiffFlag_NoListener(t *testing.T) {
	origAnalyzer := fixAnalyzer
	origRemediator := fixRemediator
	defer func() {
		fixAnalyzer = origAnalyzer
		fixRemediator = origRemediator
		diffFlag = false
	}()

	fixAnalyzer = &mockFixAnalyzer{
		err: exposure.ErrNoListener,
	}

	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"fix", "9999", "--diff"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for no listener when --diff is passed, got nil")
	}
	if !strings.Contains(err.Error(), "no listening service found on port 9999") {
		t.Errorf("expected no listening service error, got: %v", err)
	}
}
