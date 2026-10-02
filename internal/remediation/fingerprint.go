package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"lantern/internal/domain"
)

var (
	// ErrFileChanged indicates the configuration file changed between analysis and application (TOCTOU).
	ErrFileChanged = errors.New("the configuration file changed after analysis")
)

// ComputeFingerprint reads filePath and calculates its cryptographic SHA-256 fingerprint and size.
func ComputeFingerprint(filePath string) (*domain.FileFingerprint, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat file for fingerprint: %w", err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("target path is a directory: %s", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read file for fingerprint: %w", err)
	}

	sum := sha256.Sum256(data)
	return &domain.FileFingerprint{
		Path:   filePath,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// ComputeBytesFingerprint computes a file fingerprint directly from known byte contents.
func ComputeBytesFingerprint(filePath string, size int64, data []byte) *domain.FileFingerprint {
	sum := sha256.Sum256(data)
	return &domain.FileFingerprint{
		Path:   filePath,
		Size:   size,
		SHA256: hex.EncodeToString(sum[:]),
	}
}

// VerifyFingerprint checks whether the file on disk currently matches the expected fingerprint.
// Returns an error wrapping ErrFileChanged if size, content, or existence has diverged.
func VerifyFingerprint(filePath string, expected *domain.FileFingerprint) error {
	if expected == nil {
		return fmt.Errorf("cannot verify nil fingerprint against %s", filePath)
	}

	current, err := ComputeFingerprint(filePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFileChanged, err)
	}

	if current.Size != expected.Size || current.SHA256 != expected.SHA256 {
		return fmt.Errorf("%w: expected size=%d sha256=%s, found size=%d sha256=%s",
			ErrFileChanged, expected.Size, expected.SHA256, current.Size, current.SHA256)
	}

	return nil
}
