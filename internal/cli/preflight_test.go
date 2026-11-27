package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"preflight", "--help"})

	err := rootCmd.Execute()
	_ = preflightCmd.Flags().Set("help", "false")
	rootCmd.SetArgs(nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Preflight") || !strings.Contains(out, "docker compose up") {
		t.Errorf("expected preflight help description, got: %s", out)
	}
}

func TestPreflightCmd_ValidCompose(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"preflight", filePath})

	defer func() {
		preflightJSONFlag = false
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected preflight to pass on valid compose, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[OK] All ports are available on the host") {
		t.Errorf("expected [OK] banner, got: %s", out)
	}
}

func TestPreflightCmd_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"preflight", filePath, "--json"})

	defer func() {
		preflightJSONFlag = false
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"file_path":`) || !strings.Contains(out, `"passed": true`) {
		t.Errorf("expected JSON report with file_path and passed, got: %s", out)
	}
}

func TestPreflightCmd_NoFileFound(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"preflight"})

	defer func() {
		preflightJSONFlag = false
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when no compose file is present, got nil")
	}
	if !strings.Contains(err.Error(), "no compose file specified") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPreflightCmd_MultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "docker-compose.yml")
	overridePath := filepath.Join(tmpDir, "docker-compose.staging.yml")

	baseContent := `
services:
  web:
    image: nginx
    ports:
      - "127.0.0.1:18080:80"
`
	overrideContent := `
services:
  api:
    image: node
    ports:
      - "127.0.0.1:18081:3000"
`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte(overrideContent), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"preflight", basePath, overridePath})

	defer func() {
		preflightJSONFlag = false
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected multi-file preflight to pass, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Analyzed 2 declared port mapping(s).") {
		t.Errorf("expected 2 analyzed ports in output, got: %s", out)
	}
	if !strings.Contains(out, "[OK] All ports are available on the host") {
		t.Errorf("expected [OK] banner, got: %s", out)
	}
}

func TestPreflightCmd_InstallAndUninstallHook(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	defer func() {
		preflightInstallHook = false
		preflightUninstallHook = false
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	// 1. Install hook
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"preflight", tmpDir, "--install-hook"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("preflight --install-hook failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Installed pre-commit hook:") {
		t.Errorf("expected installation confirmation, got:\n%s", out)
	}

	hookFile := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookFile); err != nil {
		t.Fatalf("expected pre-commit hook file to exist: %v", err)
	}

	// 2. Uninstall hook
	buf.Reset()
	errBuf.Reset()
	preflightInstallHook = false
	preflightUninstallHook = true
	rootCmd.SetArgs([]string{"preflight", tmpDir, "--uninstall-hook"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("preflight --uninstall-hook failed: %v", err)
	}

	out = buf.String()
	if !strings.Contains(out, "Uninstalled pre-commit hook") {
		t.Errorf("expected uninstallation confirmation, got:\n%s", out)
	}

	if _, err := os.Stat(hookFile); !os.IsNotExist(err) {
		t.Errorf("expected hook file to be removed after uninstall")
	}

	// 3. Uninstall again should be a clear no-op
	buf.Reset()
	errBuf.Reset()
	preflightInstallHook = false
	preflightUninstallHook = true
	rootCmd.SetArgs([]string{"preflight", tmpDir, "--uninstall-hook"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected nil error on repeated uninstall, got: %v", err)
	}
	out = buf.String()
	if !strings.Contains(strings.ToLower(out), "not installed") {
		t.Errorf("expected not installed message on second uninstall, got:\n%s", out)
	}
}

func TestPreflightCmd_HookFlags_MutuallyExclusive(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"preflight", "--install-hook", "--uninstall-hook"})

	defer func() {
		preflightInstallHook = false
		preflightUninstallHook = false
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error on mutually exclusive hook flags, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}
