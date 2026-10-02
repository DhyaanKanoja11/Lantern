package remediation

import (
	"bytes"
	"fmt"
	"os"
)

// DetermineBackupPath returns a deterministic backup filename that does not overwrite existing backups.
func DetermineBackupPath(filePath string) (string, error) {
	primary := fmt.Sprintf("%s.lantern.bak", filePath)
	if _, err := os.Stat(primary); os.IsNotExist(err) {
		return primary, nil
	}

	for i := 1; i <= 99; i++ {
		candidate := fmt.Sprintf("%s.lantern.bak.%d", filePath, i)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("unable to allocate unique backup path for %s without overwriting existing backups", filePath)
}

// CreateBackup creates an exact, byte-verified backup of filePath before modification.
// Guarantees that existing backups are never silently overwritten.
func CreateBackup(filePath string) (string, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot backup non-existent file: %w", err)
	}
	if fi.IsDir() {
		return "", fmt.Errorf("cannot backup directory: %s", filePath)
	}

	origBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read original file for backup: %w", err)
	}

	backupPath, err := DetermineBackupPath(filePath)
	if err != nil {
		return "", err
	}

	perm := fi.Mode().Perm()
	if perm == 0 {
		perm = 0600
	}

	f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file %s: %w", backupPath, err)
	}

	if _, err := f.Write(origBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("failed to write backup data: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("failed to sync backup data: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("failed to close backup file: %w", err)
	}

	// Verify backup matches original byte-for-byte
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("failed to read back created backup: %w", err)
	}

	if !bytes.Equal(origBytes, backupBytes) {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("backup verification failed: byte mismatch between original and %s", backupPath)
	}

	return backupPath, nil
}
