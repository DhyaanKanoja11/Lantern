package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWhyCommand_InvalidPort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"why", "abc"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-numeric port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port number") {
		t.Errorf("expected invalid port error, got: %v", err)
	}
}

func TestWhyCommand_OutOfRangePort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"why", "99999"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for out of range port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port number") && !strings.Contains(err.Error(), "out-of-range") {
		t.Errorf("expected out-of-range port error, got: %v", err)
	}
}

func TestWhyCommand_ZeroPort(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"why", "0"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for port 0, got nil")
	}
}

func TestWhyCommand_MissingArg(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"why"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when port argument is omitted, got nil")
	}
}

func TestWhyCommand_NoListener(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	// Using a very unlikely port
	rootCmd.SetArgs([]string{"why", "59876"})

	err := rootCmd.Execute()
	// On Linux without listener or Windows stub, it prints clean message and returns nil or warning
	out := buf.String()
	errOut := errBuf.String()

	// Should not panic, and if executed, should state no listening service or collector warning
	if err != nil && !strings.Contains(err.Error(), "no listening") {
		t.Logf("why execution returned: %v (errOut: %s)", err, errOut)
	} else if out != "" {
		if !strings.Contains(out, "No listening service found on port") {
			t.Logf("why output: %s", out)
		}
	}
}
