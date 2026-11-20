package cli

import (
	"bytes"
	"context"
	"runtime"
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
	if runtime.GOOS == "linux" {
		if !strings.Contains(out, "Process Privilege Level") {
			t.Errorf("expected Process Privilege Level check in doctor output on Linux, got: %s", out)
		}
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

	if runtime.GOOS == "linux" {
		if !names["Process Privilege Level"] {
			t.Errorf("expected check 'Process Privilege Level' to be present in doctor checks on Linux")
		}
	} else {
		if names["Process Privilege Level"] {
			t.Errorf("expected check 'Process Privilege Level' to be absent on non-Linux")
		}
	}
}

func TestDoctorLinuxPrivilegeDiagnostic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux privilege diagnostic test on non-Linux platform")
	}

	checks := RunDoctorChecks(context.Background())
	var privCheck *DoctorCheck
	for i := range checks {
		if checks[i].Name == "Process Privilege Level" {
			privCheck = &checks[i]
			break
		}
	}

	if privCheck == nil {
		t.Fatalf("expected 'Process Privilege Level' check to be present on Linux")
	}

	if privCheck.Status != "OK" && privCheck.Status != "WARN" {
		t.Errorf("unexpected status %q for Process Privilege Level check", privCheck.Status)
	}

	if privCheck.Status == "OK" && !strings.Contains(privCheck.Message, "Running as root") {
		t.Errorf("expected root message for OK status, got: %s", privCheck.Message)
	}
	if privCheck.Status == "WARN" && !strings.Contains(privCheck.Message, "Running as unprivileged user") {
		t.Errorf("expected unprivileged message for WARN status, got: %s", privCheck.Message)
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
