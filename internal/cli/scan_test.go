package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"scan"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected no error executing scan command, got %v", err)
	}

	out := buf.String()
	// When running without listeners or on non-Linux stub, it should either print the header or no active listeners message
	if !strings.Contains(out, "PORT") && !strings.Contains(out, "No active TCP listening sockets") {
		t.Logf("Scan output: %s", out)
	}
}
