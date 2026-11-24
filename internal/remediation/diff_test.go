package remediation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestGenerateDiff_NilPlan(t *testing.T) {
	_, err := GenerateDiff(nil)
	if err == nil {
		t.Fatal("expected error for nil plan, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected nil plan error, got: %v", err)
	}
}

func TestGenerateDiff_UnsupportedStatus(t *testing.T) {
	plan := &domain.Remediation{
		Status: domain.RemediationUnsupported,
		Reason: "Native process binding",
	}
	_, err := GenerateDiff(plan)
	if err == nil {
		t.Fatal("expected error for unsupported plan, got nil")
	}
	if !strings.Contains(err.Error(), "cannot generate diff for UNSUPPORTED") {
		t.Errorf("expected UNSUPPORTED error, got: %v", err)
	}
}

func TestGenerateDiff_UnsafeStatus(t *testing.T) {
	plan := &domain.Remediation{
		Status: domain.RemediationUnsafe,
		Reason: "Ambiguous container attribution",
	}
	_, err := GenerateDiff(plan)
	if err == nil {
		t.Fatal("expected error for unsafe plan, got nil")
	}
	if !strings.Contains(err.Error(), "cannot generate diff for UNSAFE") {
		t.Errorf("expected UNSAFE error, got: %v", err)
	}
}

func TestGenerateDiff_SupportedPlan_ProducesValidGitDiff(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")

	initialContent := `version: '3.8'
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: secret
`
	if err := os.WriteFile(composePath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test compose file: %v", err)
	}

	hasGit := false
	if gitPath, err := exec.LookPath("git"); err == nil && gitPath != "" {
		hasGit = true
		initCmd := exec.Command("git", "init")
		initCmd.Dir = tmpDir
		_ = initCmd.Run()

		addCmd := exec.Command("git", "add", "docker-compose.yml")
		addCmd.Dir = tmpDir
		_ = addCmd.Run()

		commitCmd := exec.Command("git", "commit", "-m", "init")
		commitCmd.Dir = tmpDir
		_ = commitCmd.Run()
	}

	plan := &domain.Remediation{
		Status:  domain.RemediationSupported,
		Type:    "bind_localhost",
		File:    composePath,
		Line:    6,
		Service: "db",
		Before:  "0.0.0.0:5432",
		After:   "127.0.0.1:5432:5432",
	}

	remediator := NewDefaultRemediator()
	diffStr, err := remediator.Diff(context.Background(), plan)
	if err != nil {
		t.Fatalf("Diff returned unexpected error: %v", err)
	}

	// 1. Verify diff structure
	if !strings.Contains(diffStr, "--- a/docker-compose.yml") || !strings.Contains(diffStr, "+++ b/docker-compose.yml") {
		t.Fatalf("expected relative diff headers (--- a/docker-compose.yml and +++ b/docker-compose.yml), got:\n%s", diffStr)
	}
	if !strings.Contains(diffStr, "@@ -") {
		t.Fatalf("expected hunk header (@@ -), got:\n%s", diffStr)
	}
	if !strings.Contains(diffStr, `-      - "5432:5432"`) {
		t.Errorf("expected deleted line in diff, got:\n%s", diffStr)
	}
	if !strings.Contains(diffStr, `+      - "127.0.0.1:5432:5432"`) {
		t.Errorf("expected added line in diff, got:\n%s", diffStr)
	}

	// 2. Verify target file was NOT modified on disk (read-only guarantee)
	onDiskBytes, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read file on disk: %v", err)
	}
	if string(onDiskBytes) != initialContent {
		t.Fatalf("file on disk was unexpectedly modified by Diff()!")
	}

	// 3. Verify that git apply --check accepts this diff cleanly if git is available
	if hasGit {
		applyCmd := exec.Command("git", "apply", "--check")
		applyCmd.Dir = tmpDir
		applyCmd.Stdin = strings.NewReader(diffStr)
		out, err := applyCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git apply --check rejected generated diff: %v\nOutput: %s\nDiff:\n%s", err, string(out), diffStr)
		}
	}
}

func TestGenerateDiff_TentativePlan_ProducesValidGitDiff(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")

	initialContent := `services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
	if err := os.WriteFile(composePath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test compose file: %v", err)
	}

	plan := &domain.Remediation{
		Status:  domain.RemediationTentative,
		Type:    "bind_localhost",
		File:    composePath,
		Line:    5,
		Service: "web",
		Before:  "0.0.0.0:8080",
		After:   "127.0.0.1:8080:80",
	}

	diffStr, err := GenerateDiff(plan)
	if err != nil {
		t.Fatalf("GenerateDiff failed for tentative plan: %v", err)
	}

	if !strings.Contains(diffStr, `-      - "8080:80"`) || !strings.Contains(diffStr, `+      - "127.0.0.1:8080:80"`) {
		t.Errorf("diff did not contain expected changes:\n%s", diffStr)
	}
}

func TestFormatUnifiedDiff_NoChanges(t *testing.T) {
	content := []byte("line1\nline2\nline3\n")
	diffStr, err := FormatUnifiedDiff("test.txt", content, content, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diffStr != "" {
		t.Errorf("expected empty diff when no changes exist, got:\n%s", diffStr)
	}
}

func TestFormatUnifiedDiff_BoundsChecks(t *testing.T) {
	orig := []byte("line1\nline2\n")
	mod := []byte("line1\nline2\nline3\n")

	// Mismatched line count
	_, err := FormatUnifiedDiff("test.txt", orig, mod, 1)
	if err == nil {
		t.Errorf("expected error for mismatched line counts, got nil")
	}

	// Line out of range
	_, err = FormatUnifiedDiff("test.txt", orig, orig, 99)
	if err == nil {
		t.Errorf("expected error for line out of bounds, got nil")
	}
}
