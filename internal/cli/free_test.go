package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/reclaim"
)

type mockFreeAnalyzer struct {
	exposure *domain.Exposure
	err      error
}

func (m *mockFreeAnalyzer) Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.exposure, nil
}

func (m *mockFreeAnalyzer) Scan(ctx context.Context) ([]domain.ExposureSummary, error) {
	return nil, nil
}

func (m *mockFreeAnalyzer) ScanReport(ctx context.Context) (*domain.ScanReport, error) {
	return &domain.ScanReport{}, nil
}

type mockReclaimer struct {
	plan        *reclaim.ReclaimPlan
	planErr     error
	result      *reclaim.ReclaimResult
	applyErr    error
	appliedPlan *reclaim.ReclaimPlan
	forced      bool
}

func (m *mockReclaimer) Plan(ctx context.Context, exp *domain.Exposure) (*reclaim.ReclaimPlan, error) {
	if m.planErr != nil {
		return nil, m.planErr
	}
	return m.plan, nil
}

func (m *mockReclaimer) Apply(ctx context.Context, plan *reclaim.ReclaimPlan, force bool, timeout time.Duration) (*reclaim.ReclaimResult, error) {
	m.appliedPlan = plan
	m.forced = force
	if m.applyErr != nil {
		return nil, m.applyErr
	}
	return m.result, nil
}

func resetFreeFlags() {
	freeDryRunFlag = false
	freeForceFlag = false
	freeYesFlag = false
	freeTimeoutFlag = 10 * time.Second
	_ = freeCmd.Flags().Set("dry-run", "false")
	_ = freeCmd.Flags().Set("force", "false")
	_ = freeCmd.Flags().Set("yes", "false")
	_ = freeCmd.Flags().Set("timeout", "10s")
}

func TestFreeCommand_ArgumentValidation(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing port arg", []string{"free"}, "accepts 1 arg(s), received 0"},
		{"non-integer port", []string{"free", "abc"}, "invalid port number \"abc\""},
		{"zero port", []string{"free", "0"}, "port must be between 1 and 65535"},
		{"out of range port", []string{"free", "70000"}, "port must be between 1 and 65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetFreeFlags()
			buf := new(bytes.Buffer)
			errBuf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(errBuf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestFreeCommand_AlreadyFree(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	defer func() { freeAnalyzer = oldAnalyzer }()

	freeAnalyzer = &mockFreeAnalyzer{
		err: exposure.ErrNoListener,
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"free", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Port 5432 is already free") {
		t.Errorf("expected 'already free' message, got: %s", out)
	}
}

func TestFreeCommand_Container_DryRun(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 5432},
	}
	freeReclaimer = &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:          5432,
			TargetType:    reclaim.TargetContainer,
			ContainerID:   "c1234567890abcdef",
			ContainerName: "postgres-dev",
			Image:         "postgres:16",
			Project:       "my-app",
			Service:       "db",
		},
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"free", "5432", "--dry-run"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[DRY RUN]") {
		t.Errorf("expected [DRY RUN] tag, got: %s", out)
	}
	if !strings.Contains(out, "postgres-dev") {
		t.Errorf("expected container name postgres-dev, got: %s", out)
	}
	if !strings.Contains(out, "c1234567890a") {
		t.Errorf("expected truncated container ID, got: %s", out)
	}
	if !strings.Contains(out, "my-app") {
		t.Errorf("expected project name, got: %s", out)
	}
	if !strings.Contains(out, "No changes made (dry-run mode)") {
		t.Errorf("expected dry-run footer, got: %s", out)
	}
}

func TestFreeCommand_Container_Confirmed(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 5432},
	}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:          5432,
			TargetType:    reclaim.TargetContainer,
			ContainerID:   "c1234567890a",
			ContainerName: "postgres-dev",
			Image:         "postgres:16",
		},
		result: &reclaim.ReclaimResult{
			Port:        5432,
			TargetType:  reclaim.TargetContainer,
			Identifier:  "postgres-dev",
			Description: "Docker container \"postgres-dev\" stopped",
		},
	}
	freeReclaimer = mockRec

	buf := new(bytes.Buffer)
	inBuf := bytes.NewBufferString("y\n")
	rootCmd.SetOut(buf)
	rootCmd.SetIn(inBuf)
	rootCmd.SetArgs([]string{"free", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Stop this container? [y/N]:") {
		t.Errorf("expected prompt, got: %s", out)
	}
	if !strings.Contains(out, "[OK] Docker container \"postgres-dev\" stopped. Port 5432 is now free.") {
		t.Errorf("expected success message, got: %s", out)
	}
}

func TestFreeCommand_Container_Aborted(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 5432},
	}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:          5432,
			TargetType:    reclaim.TargetContainer,
			ContainerName: "postgres-dev",
		},
	}
	freeReclaimer = mockRec

	buf := new(bytes.Buffer)
	inBuf := bytes.NewBufferString("n\n")
	rootCmd.SetOut(buf)
	rootCmd.SetIn(inBuf)
	rootCmd.SetArgs([]string{"free", "5432"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[ABORTED] Port 5432 was not freed.") {
		t.Errorf("expected aborted message, got: %s", out)
	}
	if mockRec.appliedPlan != nil {
		t.Errorf("reclaimer should not have been applied when aborted")
	}
}

func TestFreeCommand_Process_ForceFlag(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 3000},
	}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:        3000,
			TargetType:  reclaim.TargetProcess,
			PID:         48212,
			ProcessName: "node",
			CommandLine: "node server.js",
			User:        "testdev",
		},
		result: &reclaim.ReclaimResult{
			Port:        3000,
			TargetType:  reclaim.TargetProcess,
			Identifier:  "48212",
			Description: "Process \"node\" (PID 48212) terminated",
		},
	}
	freeReclaimer = mockRec

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"free", "3000", "--force"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "Terminate this process?") {
		t.Errorf("prompt should be skipped with --force")
	}
	if !strings.Contains(out, "[OK] Process \"node\" (PID 48212) terminated. Port 3000 is now free.") {
		t.Errorf("expected success message, got: %s", out)
	}
	if !mockRec.forced {
		t.Errorf("expected force flag passed to reclaimer")
	}
}

func TestFreeCommand_KillAlias(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 8080},
	}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:        8080,
			TargetType:  reclaim.TargetProcess,
			PID:         1234,
			ProcessName: "caddy",
		},
		result: &reclaim.ReclaimResult{
			Port:        8080,
			TargetType:  reclaim.TargetProcess,
			Identifier:  "1234",
			Description: "Process \"caddy\" (PID 1234) terminated",
		},
	}
	freeReclaimer = mockRec

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	// Testing alias 'kill' with -y flag
	rootCmd.SetArgs([]string{"kill", "8080", "-y"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error running 'kill' alias: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[OK] Process \"caddy\" (PID 1234) terminated. Port 8080 is now free.") {
		t.Errorf("expected success message, got: %s", out)
	}
}

func TestFreeCommand_UnknownTarget(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{
		exposure: &domain.Exposure{Port: 9000},
	}
	freeReclaimer = &mockReclaimer{
		plan: &reclaim.ReclaimPlan{
			Port:       9000,
			TargetType: reclaim.TargetUnknown,
		},
	}

	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"free", "9000", "-f"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for TargetUnknown, got nil")
	}
	if !strings.Contains(err.Error(), "unprivileged or unknown listener") {
		t.Errorf("expected unprivileged/unknown error, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "elevated privileges or sudo") {
		t.Errorf("expected sudo suggestion, got: %s", out)
	}
}

// --yes only skips the prompt. It must still go through the graceful
// SIGTERM-then-wait path; only --force kills straight away.
func TestFreeCommand_YesFlagDoesNotForceKill(t *testing.T) {
	resetFreeFlags()
	defer resetFreeFlags()

	oldAnalyzer := freeAnalyzer
	oldReclaimer := freeReclaimer
	defer func() {
		freeAnalyzer = oldAnalyzer
		freeReclaimer = oldReclaimer
	}()

	freeAnalyzer = &mockFreeAnalyzer{exposure: &domain.Exposure{Port: 5432}}
	mockRec := &mockReclaimer{
		plan: &reclaim.ReclaimPlan{Port: 5432, TargetType: reclaim.TargetProcess, PID: 4242, ProcessName: "postgres"},
		result: &reclaim.ReclaimResult{
			Port:        5432,
			TargetType:  reclaim.TargetProcess,
			Description: "Process \"postgres\" (PID 4242) terminated",
		},
	}
	freeReclaimer = mockRec

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"free", "5432", "--yes"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Terminate this process?") {
		t.Error("--yes should skip the prompt")
	}
	if mockRec.appliedPlan == nil {
		t.Fatal("reclaimer was never applied")
	}
	if mockRec.forced {
		t.Error("--yes must not force kill; that's what --force is for")
	}
}
