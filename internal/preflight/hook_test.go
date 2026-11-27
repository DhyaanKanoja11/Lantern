package preflight

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallHook_FreshInstall(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	hookPath, err := InstallHook(tmpDir)
	if err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	expectedPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if hookPath != expectedPath {
		t.Errorf("expected hook path %q, got %q", expectedPath, hookPath)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read installed hook: %v", err)
	}

	strContent := string(content)
	if !strings.HasPrefix(strContent, "#!/bin/sh") {
		t.Errorf("expected POSIX sh shebang, got:\n%s", strContent)
	}
	if !strings.Contains(strContent, HookMarkerStart) || !strings.Contains(strContent, HookMarkerEnd) {
		t.Errorf("hook markers missing from content:\n%s", strContent)
	}
	if !strings.Contains(strContent, "lantern preflight") {
		t.Errorf("lantern preflight invocation missing from content:\n%s", strContent)
	}
}

func TestInstallHook_ForeignHook_Preserved(t *testing.T) {
	tmpDir := t.TempDir()
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}

	foreignContent := "#!/bin/sh\n# custom linter\necho 'running lint'\nexit 0\n"
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreignContent), 0755); err != nil {
		t.Fatal(err)
	}

	_, err := InstallHook(tmpDir)
	if err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook: %v", err)
	}

	strContent := string(content)
	if !strings.HasPrefix(strContent, foreignContent) {
		t.Errorf("foreign hook content not preserved at start:\n%s", strContent)
	}
	if !strings.Contains(strContent, HookMarkerStart) || !strings.Contains(strContent, HookMarkerEnd) {
		t.Errorf("lantern markers missing:\n%s", strContent)
	}
}

func TestInstallHook_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	hookPath, err := InstallHook(tmpDir)
	if err != nil {
		t.Fatalf("first InstallHook failed: %v", err)
	}

	contentFirst, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}

	// Second install must be a no-op
	_, err = InstallHook(tmpDir)
	if err != nil {
		t.Fatalf("second InstallHook failed: %v", err)
	}

	contentSecond, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(contentFirst, contentSecond) {
		t.Errorf("idempotent install failed: content changed between runs")
	}

	markerCount := strings.Count(string(contentSecond), HookMarkerStart)
	if markerCount != 1 {
		t.Errorf("expected exactly 1 marker, got %d", markerCount)
	}
}

func TestUninstallHook_RestoresForeignHook(t *testing.T) {
	tmpDir := t.TempDir()
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}

	foreignContent := "#!/bin/sh\n# my foreign hook\npytest\n"
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreignContent), 0755); err != nil {
		t.Fatal(err)
	}

	// Install over foreign hook
	if _, err := InstallHook(tmpDir); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	// Uninstall should restore foreign hook byte-for-byte
	result, err := UninstallHook(tmpDir)
	if err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}
	if result != hookPath {
		t.Errorf("expected uninstalled hook path %q, got %q", hookPath, result)
	}

	restored, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read restored hook: %v", err)
	}

	if string(restored) != foreignContent {
		t.Errorf("foreign hook not restored byte-for-byte.\nWant:\n%s\nGot:\n%s", foreignContent, string(restored))
	}
}

func TestUninstallHook_FreshInstall_RemovesFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	hookPath, err := InstallHook(tmpDir)
	if err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	_, err = UninstallHook(tmpDir)
	if err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	// Because file only contained shebang and lantern block, it must be removed
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Errorf("expected hook file to be deleted, but it still exists")
	}
}

func TestUninstallHook_NotInstalled_NoOp(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	msg, err := UninstallHook(tmpDir)
	if err != nil {
		t.Fatalf("expected nil error on uninstalled no-op, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(msg), "not installed") {
		t.Errorf("expected clear message indicating not installed, got: %s", msg)
	}
}

func TestInstallHook_NonGitDirectory_Error(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := InstallHook(tmpDir)
	if err == nil {
		t.Fatal("expected error on non-git directory, got nil")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("expected 'not a git repository' error, got: %v", err)
	}
}

func TestInstallHook_DotGitAsFile_Worktree(t *testing.T) {
	tmpDir := t.TempDir()
	worktreeDir := filepath.Join(tmpDir, "worktree")
	realGitDir := filepath.Join(tmpDir, "repo", ".git", "worktrees", "worktree-1")

	if err := os.MkdirAll(worktreeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realGitDir, 0755); err != nil {
		t.Fatal(err)
	}

	dotGitFile := filepath.Join(worktreeDir, ".git")
	if err := os.WriteFile(dotGitFile, []byte("gitdir: "+realGitDir+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hookPath, err := InstallHook(worktreeDir)
	if err != nil {
		t.Fatalf("InstallHook on worktree failed: %v", err)
	}

	expectedHookPath := filepath.Join(realGitDir, "hooks", "pre-commit")
	if hookPath != expectedHookPath {
		t.Errorf("expected hook in real gitdir %q, got %q", expectedHookPath, hookPath)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook in worktree target: %v", err)
	}
	if !strings.Contains(string(content), HookMarkerStart) {
		t.Errorf("marker missing from worktree hook")
	}

	// Uninstall should remove it
	if _, err := UninstallHook(worktreeDir); err != nil {
		t.Fatalf("UninstallHook failed on worktree: %v", err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Errorf("expected worktree hook file to be removed")
	}
}
