package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDoctorCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"doctor"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected doctor command to succeed, got error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Lantern Doctor - Environment Diagnostics") {
		t.Errorf("expected header in doctor output, got: %s", out)
	}
	if !strings.Contains(out, "Operating System") {
		t.Errorf("expected Operating System check in doctor output, got: %s", out)
	}
	if !strings.Contains(out, "Network Interfaces") {
		t.Errorf("expected Network Interfaces check in doctor output, got: %s", out)
	}
}

func TestRunDoctorChecks(t *testing.T) {
	checks := RunDoctorChecks(context.Background())
	if len(checks) == 0 {
		t.Fatal("expected at least one doctor check")
	}

	names := make(map[string]bool)
	for _, c := range checks {
		if c.Name == "" {
			t.Errorf("check with empty name found: %+v", c)
		}
		if c.Status != "OK" && c.Status != "WARN" && c.Status != "FAIL" {
			t.Errorf("invalid status %q in check %+v", c.Status, c)
		}
		names[c.Name] = true
	}

	expectedChecks := []string{
		"Operating System",
		"Socket Inspection Tool (ss)",
		"Process Filesystem (/proc)",
		"Docker Environment",
		"Network Interfaces",
		"Listener Collector",
	}

	for _, expected := range expectedChecks {
		if !names[expected] {
			t.Errorf("expected check %q to be present in doctor checks", expected)
		}
	}
}

func TestRenderDoctor(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "Check 1", Status: "OK", Message: "All good"},
		{Name: "Check 2", Status: "WARN", Message: "Something missing"},
		{Name: "Check 3", Status: "FAIL", Message: "Critical failure"},
	}

	var buf bytes.Buffer
	RenderDoctor(&buf, checks)
	out := buf.String()

	if !strings.Contains(out, "[OK]   Check 1: All good") {
		t.Errorf("expected formatted OK check, got:\n%s", out)
	}
	if !strings.Contains(out, "[WARN] Check 2: Something missing") {
		t.Errorf("expected formatted WARN check, got:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] Check 3: Critical failure") {
		t.Errorf("expected formatted FAIL check, got:\n%s", out)
	}
}
