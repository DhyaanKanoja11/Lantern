package process

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseComm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"postgres\n", "postgres"},
		{"sshd\r\n", "sshd"},
		{"my process\n", "my process"},
		{"", ""},
		{"   node   \n", "node"},
	}

	for _, tt := range tests {
		got := ParseComm([]byte(tt.input))
		if got != tt.expected {
			t.Errorf("ParseComm(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseCmdline(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "multiple arguments",
			input:    []byte("postgres\x00-D\x00/var/lib/postgresql/data\x00"),
			expected: "postgres -D /var/lib/postgresql/data",
		},
		{
			name:     "single argument",
			input:    []byte("/usr/sbin/sshd\x00"),
			expected: "/usr/sbin/sshd",
		},
		{
			name:     "empty cmdline",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "cmdline without trailing NUL",
			input:    []byte("node\x00server.js"),
			expected: "node server.js",
		},
		{
			name:     "arguments with spaces",
			input:    []byte("python\x00-c\x00import sys; print(sys.argv)\x00"),
			expected: "python -c import sys; print(sys.argv)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCmdline(tt.input)
			if got != tt.expected {
				t.Errorf("ParseCmdline() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseStatus(t *testing.T) {
	statusFixture := `Name:	postgres
Umask:	0077
State:	S (sleeping)
Tgid:	1234
Ngid:	0
Pid:	1234
PPid:	5678
TracerPid:	0
Uid:	999	999	999	999
Gid:	999	999	999	999
FDSize:	256
`
	name, ppid, uid, hasPPID, hasUID := ParseStatus([]byte(statusFixture))
	if name != "postgres" {
		t.Errorf("expected name 'postgres', got %q", name)
	}
	if !hasPPID || ppid != 5678 {
		t.Errorf("expected PPID 5678, got %d (has=%v)", ppid, hasPPID)
	}
	if !hasUID || uid != 999 {
		t.Errorf("expected UID 999, got %d (has=%v)", uid, hasUID)
	}
}

func TestParseStat(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPPID int
		shouldErr    bool
	}{
		{
			name:         "standard stat line",
			input:        "1234 (postgres) S 100 1234 1234 0 -1 4194304",
			expectedPPID: 100,
			shouldErr:    false,
		},
		{
			name:         "comm with spaces and nested parentheses",
			input:        "5678 (my (daemon) worker) S 200 5678 5678 0 -1 4194304",
			expectedPPID: 200,
			shouldErr:    false,
		},
		{
			name:      "missing closing parenthesis",
			input:     "1234 postgres S 100 1234",
			shouldErr: true,
		},
		{
			name:      "insufficient fields after comm",
			input:     "1234 (proc) S",
			shouldErr: true,
		},
		{
			name:      "invalid ppid integer",
			input:     "1234 (proc) S notanumber 1234",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppid, err := ParseStat([]byte(tt.input))
			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ppid != tt.expectedPPID {
				t.Errorf("ppid = %d, want %d", ppid, tt.expectedPPID)
			}
		})
	}
}

func TestInspector_ValidProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pid := 1024
	procDir := filepath.Join(tmpDir, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create mock proc dir: %v", err)
	}

	// Write mock comm
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("postgres\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Write mock cmdline
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("postgres\x00-D\x00/data\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	// Write mock status
	statusContent := "Name:\tpostgres\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(statusContent), 0644); err != nil {
		t.Fatal(err)
	}

	mockReadlink := func(p string) (string, error) {
		return "/usr/lib/postgresql/16/bin/postgres", nil
	}

	inspector := NewLinuxInspectorWithFs(tmpDir, mockReadlink)
	proc, err := inspector.Inspect(context.Background(), pid)
	if err != nil {
		t.Fatalf("unexpected inspect error: %v", err)
	}

	if proc.PID != pid {
		t.Errorf("proc.PID = %d, want %d", proc.PID, pid)
	}
	if proc.Name != "postgres" {
		t.Errorf("proc.Name = %q, want 'postgres'", proc.Name)
	}
	if proc.CommandLine != "postgres -D /data" {
		t.Errorf("proc.CommandLine = %q, want 'postgres -D /data'", proc.CommandLine)
	}
	if proc.ParentPID != 1 {
		t.Errorf("proc.ParentPID = %d, want 1", proc.ParentPID)
	}
	if proc.Executable != "/usr/lib/postgresql/16/bin/postgres" {
		t.Errorf("proc.Executable = %q, want '/usr/lib/postgresql/16/bin/postgres'", proc.Executable)
	}
	if proc.User == "" {
		t.Errorf("proc.User should not be empty")
	}
}

func TestInspector_MissingProcess(t *testing.T) {
	tmpDir := t.TempDir()
	inspector := NewLinuxInspectorWithFs(tmpDir, os.Readlink)

	proc, err := inspector.Inspect(context.Background(), 99999)
	if err == nil {
		t.Fatalf("expected error for non-existent process, got nil (proc: %+v)", proc)
	}
}

func TestInspector_EmptyCmdline(t *testing.T) {
	tmpDir := t.TempDir()
	pid := 2
	procDir := filepath.Join(tmpDir, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("kthreadd\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	inspector := NewLinuxInspectorWithFs(tmpDir, nil)
	proc, err := inspector.Inspect(context.Background(), pid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proc.Name != "kthreadd" {
		t.Errorf("proc.Name = %q, want 'kthreadd'", proc.Name)
	}
	if proc.CommandLine != "" {
		t.Errorf("proc.CommandLine should be empty for kernel worker, got %q", proc.CommandLine)
	}
}

func TestInspector_ExecutableFailure(t *testing.T) {
	tmpDir := t.TempDir()
	pid := 500
	procDir := filepath.Join(tmpDir, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("daemon\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Mock readlink that fails with permission error
	mockReadlink := func(p string) (string, error) {
		return "", os.ErrPermission
	}

	inspector := NewLinuxInspectorWithFs(tmpDir, mockReadlink)
	proc, err := inspector.Inspect(context.Background(), pid)
	if err != nil {
		t.Fatalf("inspection should not fail when executable readlink fails, got error: %v", err)
	}

	if proc.Executable != "" {
		t.Errorf("expected empty executable path on readlink failure, got %q", proc.Executable)
	}
	if proc.Name != "daemon" {
		t.Errorf("expected process name 'daemon', got %q", proc.Name)
	}
}

func TestInspector_StatFallback(t *testing.T) {
	tmpDir := t.TempDir()
	pid := 700
	procDir := filepath.Join(tmpDir, strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}

	// No status file, only comm and stat
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte("worker\n"), 0644); err != nil {
		t.Fatal(err)
	}
	statContent := "700 (worker) S 42 700 700 0 -1"
	if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte(statContent), 0644); err != nil {
		t.Fatal(err)
	}

	inspector := NewLinuxInspectorWithFs(tmpDir, nil)
	proc, err := inspector.Inspect(context.Background(), pid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proc.ParentPID != 42 {
		t.Errorf("proc.ParentPID = %d, want 42 (from stat)", proc.ParentPID)
	}
}

func TestInspector_InvalidPID(t *testing.T) {
	inspector := NewLinuxInspectorWithFs(t.TempDir(), nil)
	_, err := inspector.Inspect(context.Background(), 0)
	if err == nil {
		t.Errorf("expected error for PID 0, got nil")
	}
	_, err = inspector.Inspect(context.Background(), -1)
	if err == nil {
		t.Errorf("expected error for negative PID, got nil")
	}
}
