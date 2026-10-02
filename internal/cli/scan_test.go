package cli

import (
	"bytes"
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
}
