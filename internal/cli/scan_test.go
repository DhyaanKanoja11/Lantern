package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestScanCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatalf("expected error on non-Linux OS, got nil")
		}
		if !strings.Contains(err.Error(), "Linux") {
			t.Errorf("expected Linux requirement in error message, got: %v", err)
		}
		return
	}

	if err != nil {
		t.Fatalf("expected no error executing scan command, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "PORT") && !strings.Contains(out, "No active TCP listening sockets") {
		t.Logf("Scan output: %s", out)
	}
}
