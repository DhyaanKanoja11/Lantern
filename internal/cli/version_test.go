package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected no error executing version command, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "lantern "+Version) {
		t.Errorf("expected version output to contain 'lantern %s', got: %s", Version, out)
	}
}

func TestFormatVersion(t *testing.T) {
	origCommit := Commit
	origDate := Date
	defer func() {
		Commit = origCommit
		Date = origDate
	}()

	// Case 1: Default build (no ldflags)
	Commit = "none"
	Date = "unknown"
	vDefault := FormatVersion()
	if vDefault != "lantern "+Version {
		t.Errorf("expected default format 'lantern %s', got %s", Version, vDefault)
	}

	// Case 2: Injected build metadata via ldflags
	Commit = "a1b2c3d"
	Date = "2026-11-20T12:00:00Z"
	vStamped := FormatVersion()
	if !strings.Contains(vStamped, "commit: a1b2c3d") || !strings.Contains(vStamped, "built: 2026-11-20T12:00:00Z") {
		t.Errorf("expected stamped metadata in version string, got: %s", vStamped)
	}
}
