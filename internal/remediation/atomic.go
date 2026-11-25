package remediation

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite safely replaces filePath with data via a temporary file in the same directory.
// Ensures that failures never leave a truncated or partially written file.
//
// If filePath is a symlink the target is rewritten and the link is left in
// place. The original file's owner is carried over to the new file.
func AtomicWrite(filePath string, data []byte, perm os.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(filePath); err == nil {
		filePath = resolved
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to resolve %s: %w", filePath, err)
	}
	origInfo, statErr := os.Stat(filePath)

	dir := filepath.Dir(filePath)
	tmpFile, err := os.CreateTemp(dir, ".lantern-fix-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup on failure
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write data to temporary file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to flush temporary file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if perm != 0 {
		if err := os.Chmod(tmpPath, perm); err != nil {
			return fmt.Errorf("failed to set permissions on temporary file: %w", err)
		}
	}

	if statErr == nil {
		if err := copyOwner(tmpPath, origInfo); err != nil {
			return fmt.Errorf("failed to preserve owner of %s: %w", filePath, err)
		}
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to atomically replace %s: %w", filePath, err)
	}

	cleanup = false
	return nil
}
