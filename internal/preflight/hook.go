package preflight

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/remediation"
)

const (
	// HookMarkerStart begins the Lantern managed section in a Git hook.
	HookMarkerStart = "# >>> lantern preflight >>>"
	// HookMarkerEnd terminates the Lantern managed section in a Git hook.
	HookMarkerEnd = "# <<< lantern preflight <<<"
)

// HookBlock is the POSIX sh script inserted into pre-commit hooks.
var HookBlock = HookMarkerStart + `
if command -v lantern >/dev/null 2>&1; then
    lantern preflight || exit $?
else
    echo "Notice: lantern not found on PATH; skipping preflight check." >&2
fi
` + HookMarkerEnd

// FindGitDir locates the git directory for a repository, resolving .git files (worktrees/submodules).
func FindGitDir(repoDir string) (string, error) {
	if repoDir == "" {
		repoDir = "."
	}

	cleanDir, err := filepath.Abs(repoDir)
	if err != nil {
		cleanDir = repoDir
	}

	dotGit := filepath.Join(cleanDir, ".git")
	fi, err := os.Stat(dotGit)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("not a git repository (missing .git): %s", repoDir)
		}
		return "", fmt.Errorf("failed to access %s: %w", dotGit, err)
	}

	if fi.IsDir() {
		return dotGit, nil
	}

	// .git is a file (e.g. worktree or submodule pointer)
	content, err := os.ReadFile(dotGit)
	if err != nil {
		return "", fmt.Errorf("failed to read gitdir file %s: %w", dotGit, err)
	}

	var gitdir string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), "gitdir:") {
			gitdir = strings.TrimSpace(line[len("gitdir:"):])
			break
		}
	}
	if gitdir == "" {
		return "", fmt.Errorf("invalid gitdir file format in %s: missing 'gitdir:' directive", dotGit)
	}

	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Clean(filepath.Join(cleanDir, gitdir))
	}

	gfi, err := os.Stat(gitdir)
	if err != nil {
		return "", fmt.Errorf("gitdir target does not exist (%s): %w", gitdir, err)
	}
	if !gfi.IsDir() {
		return "", fmt.Errorf("gitdir target is not a directory: %s", gitdir)
	}

	return gitdir, nil
}

// FindHooksDir resolves the hooks directory for the repository, ensuring it exists.
func FindHooksDir(repoDir string) (string, error) {
	gitDir, err := FindGitDir(repoDir)
	if err != nil {
		return "", err
	}
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create hooks directory %s: %w", hooksDir, err)
	}
	return hooksDir, nil
}

// InstallHook installs the preflight pre-commit hook in repoDir.
// If no hook exists, it creates one with mode 0755 using atomic write.
// If a hook exists, it appends the delimited block idempotently.
func InstallHook(repoDir string) (string, error) {
	hooksDir, err := FindHooksDir(repoDir)
	if err != nil {
		return "", err
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to read existing pre-commit hook at %s: %w", hookPath, err)
		}
		// Fresh install: write shebang and block with mode 0755
		freshContent := "#!/bin/sh\n\n" + HookBlock + "\n"
		if err := remediation.AtomicWrite(hookPath, []byte(freshContent), 0755); err != nil {
			return "", fmt.Errorf("failed to install pre-commit hook: %w", err)
		}
		return hookPath, nil
	}

	// Pre-commit hook already exists
	contentStr := string(existing)
	if strings.Contains(contentStr, HookMarkerStart) && strings.Contains(contentStr, HookMarkerEnd) {
		// Idempotent: already installed
		return hookPath, nil
	}

	var newContent string
	if !strings.HasSuffix(contentStr, "\n") {
		newContent = contentStr + "\n\n" + HookBlock + "\n"
	} else {
		newContent = contentStr + "\n" + HookBlock + "\n"
	}

	// Preserve existing permissions, ensuring execute bit is set
	perm := os.FileMode(0755)
	if fi, err := os.Stat(hookPath); err == nil {
		perm = fi.Mode().Perm() | 0111
	}

	if err := remediation.AtomicWrite(hookPath, []byte(newContent), perm); err != nil {
		return "", fmt.Errorf("failed to update pre-commit hook: %w", err)
	}
	return hookPath, nil
}

// UninstallHook removes only the lantern preflight block from repoDir's pre-commit hook.
// If the hook is then empty or only contains a shebang, it removes the file.
// If the hook was not installed, it returns a message indicating so with nil error.
func UninstallHook(repoDir string) (string, error) {
	gitDir, err := FindGitDir(repoDir)
	if err != nil {
		return "", err
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "Lantern preflight hook is not installed.", nil
		}
		return "", fmt.Errorf("failed to read pre-commit hook at %s: %w", hookPath, err)
	}

	contentStr := string(existing)
	startIdx := strings.Index(contentStr, HookMarkerStart)
	endMarkerIdx := strings.Index(contentStr, HookMarkerEnd)
	if startIdx == -1 || endMarkerIdx == -1 || endMarkerIdx < startIdx {
		return "Lantern preflight hook is not installed.", nil
	}

	endIdx := endMarkerIdx + len(HookMarkerEnd)

	// Consume leading newline added during installation if present
	start := startIdx
	if start > 0 && contentStr[start-1] == '\n' {
		start--
	}
	// Consume trailing newline if present
	end := endIdx
	if end < len(contentStr) && contentStr[end] == '\n' {
		end++
	}

	remaining := contentStr[:start] + contentStr[end:]

	if isOnlyShebangOrEmpty(remaining) {
		if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to remove empty pre-commit hook: %w", err)
		}
		return hookPath, nil
	}

	perm := os.FileMode(0755)
	if fi, err := os.Stat(hookPath); err == nil {
		perm = fi.Mode().Perm()
	}

	if err := remediation.AtomicWrite(hookPath, []byte(remaining), perm); err != nil {
		return "", fmt.Errorf("failed to update pre-commit hook: %w", err)
	}
	return hookPath, nil
}

func isOnlyShebangOrEmpty(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return true
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) == 1 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#!") {
		return true
	}
	return false
}
