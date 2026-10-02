package remediation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFingerprint_Unchanged(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "docker-compose.yml")
	content := []byte("services:\n  db:\n    ports:\n      - 5432:5432\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	fp, err := ComputeFingerprint(path)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	if err := VerifyFingerprint(path, fp); err != nil {
		t.Errorf("expected unchanged file to verify, got: %v", err)
	}
}

func TestVerifyFingerprint_Modified(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "docker-compose.yml")
	content := []byte("services:\n  db:\n    ports:\n      - 5432:5432\n")
	_ = os.WriteFile(path, content, 0644)

	fp, err := ComputeFingerprint(path)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	// Modify file before verify
	modified := []byte("services:\n  db:\n    ports:\n      - 5432:5432\n  extra: true\n")
	_ = os.WriteFile(path, modified, 0644)

	err = VerifyFingerprint(path, fp)
	if err == nil {
		t.Fatal("expected modified file to fail fingerprint verification, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged, got: %v", err)
	}
}

func TestVerifyFingerprint_SameSizeModified(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "docker-compose.yml")
	// "5432:5432" vs "5433:5433" - exactly identical byte size (43 bytes)
	c1 := []byte("services:\n  db:\n    ports:\n      - 5432:5432\n")
	c2 := []byte("services:\n  db:\n    ports:\n      - 5433:5433\n")
	if len(c1) != len(c2) {
		t.Fatalf("test invariant broken: c1 and c2 must be identical size")
	}

	_ = os.WriteFile(path, c1, 0644)
	fp, err := ComputeFingerprint(path)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	// Overwrite with same-size different content
	_ = os.WriteFile(path, c2, 0644)

	err = VerifyFingerprint(path, fp)
	if err == nil {
		t.Fatal("expected same-size modified file to fail fingerprint verification, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged, got: %v", err)
	}
}

func TestVerifyFingerprint_Deleted(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "docker-compose.yml")
	content := []byte("services:\n  db:\n    ports:\n      - 5432:5432\n")
	_ = os.WriteFile(path, content, 0644)

	fp, err := ComputeFingerprint(path)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	// Delete file
	_ = os.Remove(path)

	err = VerifyFingerprint(path, fp)
	if err == nil {
		t.Fatal("expected deleted file to fail fingerprint verification, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged for deleted file, got: %v", err)
	}
}

func TestVerifyFingerprint_NilExpected(t *testing.T) {
	err := VerifyFingerprint("some-path", nil)
	if err == nil {
		t.Fatal("expected error for nil expected fingerprint, got nil")
	}
}
