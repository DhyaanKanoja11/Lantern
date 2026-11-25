package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		"Docker Environment",
		"Network Interfaces",
		"Listener Collector",
	}

	switch runtime.GOOS {
	case "linux":
		expectedChecks = append(expectedChecks, "Socket Inspection Tool (ss)", "Process Filesystem (/proc)", "Process Privilege Level")
	case "darwin":
		expectedChecks = append(expectedChecks, "Socket Inspection Tool (lsof)", "Process Inspection Tool (ps)")
	case "windows":
		expectedChecks = append(expectedChecks, "Socket Inspection Tool (netstat)", "Process Inspection Tool (tasklist)")
	}

	for _, expected := range expectedChecks {
		if !names[expected] {
			t.Errorf("expected check %q to be present in doctor checks", expected)
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

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return os.ModeSocket | 0660 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

func baseTestDoctorDeps() doctorDeps {
	return doctorDeps{
		goos:     "linux",
		geteuid:  func() int { return 1000 },
		getenv:   func(string) string { return "" },
		lookPath: func(name string) (string, error) { return "", errors.New("not found") },
		stat:     func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		isDockerAvailable: func(context.Context) bool {
			return false
		},
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "lo"}}, nil
		},
		checkListeners: func(context.Context) error { return nil },
	}
}

func TestDoctor_PodmanDetectedWithSocket(t *testing.T) {
	deps := baseTestDoctorDeps()
	deps.lookPath = func(name string) (string, error) {
		if name == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", errors.New("not found")
	}
	expectedSocket := filepath.Clean("/run/user/1000/podman/podman.sock")
	deps.stat = func(name string) (os.FileInfo, error) {
		if filepath.Clean(name) == expectedSocket {
			return fakeFileInfo{name: "podman.sock"}, nil
		}
		return nil, os.ErrNotExist
	}

	check := checkContainerRuntime(context.Background(), deps)
	if check.Name != "Docker Environment" {
		t.Errorf("expected check name 'Docker Environment', got %q", check.Name)
	}
	if check.Status != "OK" {
		t.Errorf("expected OK status when podman CLI and socket are present, got %q (%s)", check.Status, check.Message)
	}
	if !strings.Contains(check.Message, "Podman CLI (/usr/bin/podman)") || !strings.Contains(check.Message, expectedSocket) {
		t.Errorf("unexpected Podman message: %s", check.Message)
	}
}

func TestDoctor_PodmanDetectedWithoutSocket(t *testing.T) {
	deps := baseTestDoctorDeps()
	deps.lookPath = func(name string) (string, error) {
		if name == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", errors.New("not found")
	}

	check := checkContainerRuntime(context.Background(), deps)
	if check.Status != "WARN" {
		t.Errorf("expected WARN status when podman socket is missing, got %q", check.Status)
	}
	if !strings.Contains(check.Message, "Podman CLI found (/usr/bin/podman)") || !strings.Contains(check.Message, "no Podman socket was detected") {
		t.Errorf("unexpected Podman missing socket message: %s", check.Message)
	}
}

func TestDoctor_PodmanMacOSMachineSocket(t *testing.T) {
	deps := baseTestDoctorDeps()
	deps.goos = "darwin"
	deps.getenv = func(k string) string {
		if k == "HOME" {
			return "/Users/dev"
		}
		return ""
	}
	deps.lookPath = func(name string) (string, error) {
		if name == "podman" {
			return "/opt/homebrew/bin/podman", nil
		}
		return "", errors.New("not found")
	}
	expectedSocket := filepath.Clean("/Users/dev/.local/share/containers/podman/machine/podman.sock")
	deps.stat = func(name string) (os.FileInfo, error) {
		if filepath.Clean(name) == expectedSocket {
			return fakeFileInfo{name: "podman.sock"}, nil
		}
		return nil, os.ErrNotExist
	}

	check := checkContainerRuntime(context.Background(), deps)
	if check.Status != "OK" {
		t.Errorf("expected OK status on darwin podman machine socket, got %q (%s)", check.Status, check.Message)
	}
	if !strings.Contains(check.Message, expectedSocket) {
		t.Errorf("expected socket path %q in message: %s", expectedSocket, check.Message)
	}
}

func TestDoctor_DockerAndPodmanAbsent(t *testing.T) {
	deps := baseTestDoctorDeps()

	check := checkContainerRuntime(context.Background(), deps)
	if check.Status != "WARN" {
		t.Errorf("expected WARN status when neither docker nor podman exists, got %q", check.Status)
	}
	if !strings.Contains(check.Message, "Docker or Podman CLI not found") {
		t.Errorf("unexpected absent runtime message: %s", check.Message)
	}
}

func TestDoctor_DockerPreferredOverPodman(t *testing.T) {
	deps := baseTestDoctorDeps()
	deps.lookPath = func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		if name == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", errors.New("not found")
	}
	deps.isDockerAvailable = func(context.Context) bool { return true }

	check := checkContainerRuntime(context.Background(), deps)
	if check.Status != "OK" {
		t.Errorf("expected OK status, got %q", check.Status)
	}
	if !strings.Contains(check.Message, "Docker CLI (/usr/bin/docker)") {
		t.Errorf("expected Docker CLI message when docker is available, got: %s", check.Message)
	}
}
