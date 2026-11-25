package cli

import (
	"bytes"
	"context"
	"errors"
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

	if !names["Docker Environment"] && !names["Container Environment"] {
		t.Errorf("expected either 'Docker Environment' or 'Container Environment' check to be present, got: %v", names)
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

type mockFileInfo struct {
	name string
	mode os.FileMode
	dir  bool
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return m.dir }
func (m mockFileInfo) Sys() any           { return nil }

func newTestDoctorDeps(goos string, binaries map[string]string, env map[string]string, sockets map[string]bool) doctorDeps {
	return doctorDeps{
		goos: goos,
		lookPath: func(file string) (string, error) {
			if p, ok := binaries[file]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		},
		isDockerAvail: func(ctx context.Context) bool { return false },
		probePodman:   func(ctx context.Context, podmanPath string) bool { return false },
		statPath: func(p string) (os.FileInfo, error) {
			if isSock, ok := sockets[p]; ok {
				if isSock {
					return mockFileInfo{name: p, mode: os.ModeSocket}, nil
				}
				return mockFileInfo{name: p, mode: 0o644}, nil
			}
			return nil, os.ErrNotExist
		},
		getenv: func(k string) string {
			return env[k]
		},
		getuid:      func() int { return 1000 },
		userHomeDir: func() (string, error) { return "/home/tester", nil },
	}
}

func TestCheckContainerRuntime_Docker(t *testing.T) {
	t.Run("docker CLI and daemon reachable", func(t *testing.T) {
		deps := newTestDoctorDeps("linux", map[string]string{"docker": "/usr/bin/docker", "podman": "/usr/bin/podman"}, nil, nil)
		deps.isDockerAvail = func(ctx context.Context) bool { return true }

		check := checkContainerRuntime(context.Background(), deps)
		if check.Name != "Docker Environment" || check.Status != "OK" {
			t.Fatalf("unexpected check: %+v", check)
		}
		if !strings.Contains(check.Message, "/usr/bin/docker") || !strings.Contains(check.Message, "reachable") {
			t.Errorf("unexpected message: %s", check.Message)
		}
	})

	t.Run("docker CLI found but daemon unavailable", func(t *testing.T) {
		deps := newTestDoctorDeps("linux", map[string]string{"docker": "/usr/bin/docker"}, nil, nil)
		check := checkContainerRuntime(context.Background(), deps)
		if check.Name != "Docker Environment" || check.Status != "WARN" {
			t.Fatalf("unexpected check: %+v", check)
		}
		if !strings.Contains(check.Message, "daemon is not accessible") {
			t.Errorf("unexpected message: %s", check.Message)
		}
	})
}

func TestCheckContainerRuntime_Podman(t *testing.T) {
	cases := []struct {
		name           string
		goos           string
		binaries       map[string]string
		env            map[string]string
		uid            int
		sockets        map[string]bool
		probeOK        bool
		wantStatus     string
		wantSubstrings []string
	}{
		{
			name:       "linux rootless default socket and reachable engine",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			uid:        1000,
			sockets:    map[string]bool{"/run/user/1000/podman/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"/usr/bin/podman",
				"/run/user/1000/podman/podman.sock",
			},
		},
		{
			name:       "linux custom XDG_RUNTIME_DIR socket",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			env:        map[string]string{"XDG_RUNTIME_DIR": "/tmp/xdg-1001"},
			uid:        1001,
			sockets:    map[string]bool{"/tmp/xdg-1001/podman/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"/tmp/xdg-1001/podman/podman.sock",
			},
		},
		{
			name:       "linux rootful socket fallback",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			uid:        1000,
			sockets:    map[string]bool{"/run/podman/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"/run/podman/podman.sock",
			},
		},
		{
			name:       "linux sudo preserves SUDO_UID user socket",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			env:        map[string]string{"SUDO_UID": "1000"},
			uid:        0,
			sockets:    map[string]bool{"/run/user/1000/podman/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"/run/user/1000/podman/podman.sock",
			},
		},
		{
			name:       "CONTAINER_HOST unix socket prioritized",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			env:        map[string]string{"CONTAINER_HOST": "unix:///var/tmp/custom-podman.sock"},
			uid:        1000,
			sockets:    map[string]bool{"/var/tmp/custom-podman.sock": true, "/run/user/1000/podman/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"/var/tmp/custom-podman.sock",
			},
		},
		{
			name:       "linux rootless CLI reachable without API socket",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			uid:        1000,
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"CLI reachable",
				"no Podman socket found",
			},
		},
		{
			name:       "linux socket exists but engine probe fails",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			uid:        1000,
			sockets:    map[string]bool{"/run/user/1000/podman/podman.sock": true},
			probeOK:    false,
			wantStatus: "WARN",
			wantSubstrings: []string{
				"Podman CLI found",
				"/run/user/1000/podman/podman.sock",
				"not accessible",
			},
		},
		{
			name:       "linux regular file at socket path is ignored",
			goos:       "linux",
			binaries:   map[string]string{"podman": "/usr/bin/podman"},
			uid:        1000,
			sockets:    map[string]bool{"/run/user/1000/podman/podman.sock": false},
			probeOK:    false,
			wantStatus: "WARN",
			wantSubstrings: []string{
				"no Podman socket found",
				"not accessible",
			},
		},
		{
			name:       "darwin podman machine applehv socket",
			goos:       "darwin",
			binaries:   map[string]string{"podman": "/opt/homebrew/bin/podman"},
			sockets:    map[string]bool{"/home/tester/.local/share/containers/podman/machine/applehv/podman.sock": true},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"/opt/homebrew/bin/podman",
				"/home/tester/.local/share/containers/podman/machine/applehv/podman.sock",
			},
		},
		{
			name:       "windows podman machine reachable via CLI",
			goos:       "windows",
			binaries:   map[string]string{"podman": `C:\Program Files\RedHat\Podman\podman.exe`},
			probeOK:    true,
			wantStatus: "OK",
			wantSubstrings: []string{
				"Podman container engine detected",
				"CLI reachable",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTestDoctorDeps(tc.goos, tc.binaries, tc.env, tc.sockets)
			deps.getuid = func() int { return tc.uid }
			deps.probePodman = func(ctx context.Context, podmanPath string) bool { return tc.probeOK }

			check := checkContainerRuntime(context.Background(), deps)
			if check.Name != "Container Environment" {
				t.Errorf("expected Name 'Container Environment', got %q", check.Name)
			}
			if check.Status != tc.wantStatus {
				t.Errorf("expected Status %q, got %q (message: %s)", tc.wantStatus, check.Status, check.Message)
			}
			for _, sub := range tc.wantSubstrings {
				if !strings.Contains(check.Message, sub) {
					t.Errorf("expected message %q to contain %q", check.Message, sub)
				}
			}
		})
	}
}

func TestCheckContainerRuntime_NeitherPresent(t *testing.T) {
	deps := newTestDoctorDeps("linux", map[string]string{}, nil, nil)
	check := checkContainerRuntime(context.Background(), deps)

	if check.Name != "Container Environment" {
		t.Errorf("expected Name 'Container Environment', got %q", check.Name)
	}
	if check.Status != "WARN" {
		t.Errorf("expected Status 'WARN', got %q", check.Status)
	}
	if !strings.Contains(check.Message, "Neither Docker nor Podman CLI found in PATH") {
		t.Errorf("unexpected message: %s", check.Message)
	}
}

func TestPodmanSocketCandidates_DeduplicationAndValidation(t *testing.T) {
	deps := newTestDoctorDeps("linux", nil, map[string]string{
		"CONTAINER_HOST":  "tcp://127.0.0.1:8080",
		"DOCKER_HOST":     "ssh://user@host/run/podman/podman.sock",
		"XDG_RUNTIME_DIR": "/run/user/1000",
	}, nil)
	deps.getuid = func() int { return 1000 }

	candidates := podmanSocketCandidates(deps)
	expected := []string{
		"/run/user/1000/podman/podman.sock",
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	}

	if len(candidates) != len(expected) {
		t.Fatalf("expected %d candidates %v, got %d %v", len(expected), expected, len(candidates), candidates)
	}
	for i := range expected {
		if candidates[i] != expected[i] {
			t.Errorf("candidate[%d] = %q, want %q", i, candidates[i], expected[i])
		}
	}
}

func TestParseUnixSocketHost(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"unix:///run/user/1000/podman/podman.sock", "/run/user/1000/podman/podman.sock"},
		{"  unix:///var/run/podman/podman.sock  ", "/var/run/podman/podman.sock"},
		{"/run/podman/podman.sock", "/run/podman/podman.sock"},
		{"unix://relative/podman.sock", ""},
		{"tcp://127.0.0.1:2375", ""},
		{"npipe:////./pipe/podman-machine-default", ""},
		{"", ""},
	}

	for _, tc := range cases {
		if got := parseUnixSocketHost(tc.input); got != tc.want {
			t.Errorf("parseUnixSocketHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIsUnixSocket_RealFilesystemNonSocketsRejected(t *testing.T) {
	tmpDir := t.TempDir()
	regFile := filepath.Join(tmpDir, "podman.sock")
	if err := os.WriteFile(regFile, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	if isUnixSocket(os.Stat, tmpDir) {
		t.Errorf("expected directory %q not to be treated as Unix socket", tmpDir)
	}
	if isUnixSocket(os.Stat, regFile) {
		t.Errorf("expected regular file %q not to be treated as Unix socket", regFile)
	}
	if isUnixSocket(os.Stat, filepath.Join(tmpDir, "missing.sock")) {
		t.Errorf("expected missing file not to be treated as Unix socket")
	}
}
