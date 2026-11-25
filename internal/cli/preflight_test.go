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
