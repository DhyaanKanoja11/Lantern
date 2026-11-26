package remediation

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// GenerateDiff computes a standard Git unified diff (with 3 lines of context)
// representing the remediation change for the given plan.
func GenerateDiff(plan *domain.Remediation) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("cannot generate diff: remediation plan is nil")
	}

	if plan.Status != domain.RemediationSupported && plan.Status != domain.RemediationTentative {
		return "", fmt.Errorf("cannot generate diff for %s exposure: %s", plan.Status, plan.Reason)
	}

	if plan.File == "" {
		return "", fmt.Errorf("cannot generate diff: target configuration file path is empty")
	}

	origBytes, err := os.ReadFile(plan.File)
	if err != nil {
		return "", fmt.Errorf("failed to read target file %s: %w", plan.File, err)
	}

	modBytes, err := ApplyComposeFix(plan.File, plan.Service, plan.Line, 0, plan.After)
	if err != nil {
		return "", fmt.Errorf("failed to compute remediation patch: %w", err)
	}

	relPath := resolveGitRelativePath(plan.File)

	return FormatUnifiedDiff(relPath, origBytes, modBytes, plan.Line)
}

func resolveGitRelativePath(filePath string) string {
	if !filepath.IsAbs(filePath) {
		clean := filepath.ToSlash(filepath.Clean(filePath))
		return strings.TrimPrefix(clean, "./")
	}

	// 1. Try relative to current working directory
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, filePath); err == nil && !strings.HasPrefix(rel, "..") {
			clean := filepath.ToSlash(filepath.Clean(rel))
			return strings.TrimPrefix(clean, "./")
		}
	}

	// 2. Walk up ancestor directories to find Git root (.git)
	dir := filepath.Dir(filePath)
	for {
		gitPath := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitPath); err == nil {
			if rel, err := filepath.Rel(dir, filePath); err == nil {
				clean := filepath.ToSlash(filepath.Clean(rel))
				return strings.TrimPrefix(clean, "./")
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// 3. Fallback to file base name
	return filepath.Base(filePath)
}

// FormatUnifiedDiff formats two byte buffers into standard Git unified diff format
// centered around targetLine (1-indexed) with 3 lines of surrounding context.
func FormatUnifiedDiff(relPath string, origBytes, modBytes []byte, targetLine int) (string, error) {
	origLines, origTrailingNewline := splitDiffLines(origBytes)
	modLines, _ := splitDiffLines(modBytes)

	if len(origLines) != len(modLines) {
		return "", fmt.Errorf("diff generation error: line count mismatch (original: %d, modified: %d)", len(origLines), len(modLines))
	}

	if targetLine < 1 || targetLine > len(origLines) {
		return "", fmt.Errorf("target line %d is outside file bounds (%d lines)", targetLine, len(origLines))
	}

	targetIdx := targetLine - 1
	if origLines[targetIdx] == modLines[targetIdx] {
		return "", nil // No changes
	}

	startIdx := targetIdx - 3
	if startIdx < 0 {
		startIdx = 0
	}

	endIdx := targetIdx + 1 + 3
	if endIdx > len(origLines) {
		endIdx = len(origLines)
	}

	hunkLineCount := endIdx - startIdx
	startLineNum := startIdx + 1

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", relPath)
	fmt.Fprintf(&b, "+++ b/%s\n", relPath)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", startLineNum, hunkLineCount, startLineNum, hunkLineCount)

	// Context before
	for i := startIdx; i < targetIdx; i++ {
		b.WriteString(" ")
		b.WriteString(origLines[i])
		b.WriteString("\n")
	}

	// Deleted original line
	b.WriteString("-")
	b.WriteString(origLines[targetIdx])
	b.WriteString("\n")

	// Added modified line
	b.WriteString("+")
	b.WriteString(modLines[targetIdx])
	b.WriteString("\n")

	// Context after
	for i := targetIdx + 1; i < endIdx; i++ {
		b.WriteString(" ")
		b.WriteString(origLines[i])
		b.WriteString("\n")
	}

	if !origTrailingNewline && endIdx == len(origLines) {
		b.WriteString("\\ No newline at end of file\n")
	}

	return b.String(), nil
}

func splitDiffLines(data []byte) ([]string, bool) {
	if len(data) == 0 {
		return nil, false
	}
	hasTrailingNewline := data[len(data)-1] == '\n'
	content := string(bytes.TrimSuffix(data, []byte("\n")))
	content = strings.TrimSuffix(content, "\r")
	raw := strings.Split(content, "\n")
	for i := range raw {
		raw[i] = strings.TrimSuffix(raw[i], "\r")
	}
	return raw, hasTrailingNewline
}
