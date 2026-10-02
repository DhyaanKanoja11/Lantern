package process

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"lantern/internal/domain"
)

// LinuxInspector discovers process details by reading /proc/<pid> files.
type LinuxInspector struct {
	baseDir      string
	readlinkFunc func(string) (string, error)
}

// NewLinuxInspector creates an inspector targeting the specified /proc directory (typically "/proc").
func NewLinuxInspector(baseDir string) *LinuxInspector {
	return NewLinuxInspectorWithFs(baseDir, os.Readlink)
}

// NewLinuxInspectorWithFs allows injecting a custom base directory and readlink function for deterministic testing.
func NewLinuxInspectorWithFs(baseDir string, readlink func(string) (string, error)) *LinuxInspector {
	return &LinuxInspector{
		baseDir:      baseDir,
		readlinkFunc: readlink,
	}
}

// Inspect gathers metadata for the given PID without reading environment variables.
func (i *LinuxInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID: %d", pid)
	}

	procDir := filepath.Join(i.baseDir, strconv.Itoa(pid))
	info, err := os.Stat(procDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("process %d does not exist (may have exited)", pid)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied reading /proc/%d", pid)
		}
		return nil, fmt.Errorf("failed to access /proc/%d: %w", pid, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("/proc/%d is not a directory", pid)
	}

	proc := &domain.Process{
		PID: pid,
	}

	// 1. Process name from /proc/<pid>/comm
	if commData, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		proc.Name = ParseComm(commData)
	}

	// 2. Command line from /proc/<pid>/cmdline (NUL-separated arguments, never /proc/<pid>/environ)
	if cmdData, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		proc.CommandLine = ParseCmdline(cmdData)
	}

	// 3. Status details (PPID, UID, Name fallback) from /proc/<pid>/status
	var hasStatusPPID bool
	if statusData, err := os.ReadFile(filepath.Join(procDir, "status")); err == nil {
		statusName, ppid, uid, hasPPID, hasUID := ParseStatus(statusData)
		if proc.Name == "" && statusName != "" {
			proc.Name = statusName
		}
		if hasPPID {
			proc.ParentPID = ppid
			hasStatusPPID = true
		}
		if hasUID {
			proc.User = resolveUser(uid)
		}
	}

	// 4. Fallback for PPID if status was unreadable or lacked PPid
	if !hasStatusPPID {
		if statData, err := os.ReadFile(filepath.Join(procDir, "stat")); err == nil {
			if ppid, err := ParseStat(statData); err == nil {
				proc.ParentPID = ppid
			}
		}
	}

	// 5. Executable path via /proc/<pid>/exe symlink
	if i.readlinkFunc != nil {
		exePath, err := i.readlinkFunc(filepath.Join(procDir, "exe"))
		if err == nil {
			proc.Executable = exePath
		}
		// If readlink fails due to permission, missing target, or kernel worker,
		// we leave Executable as "" without failing the entire inspection.
	}

	return proc, nil
}

// Correlate implements ProcessCorrelator by delegating to Inspect.
func (i *LinuxInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return i.Inspect(ctx, pid)
}

// resolveUser attempts to look up username from UID, falling back to numeric UID string.
func resolveUser(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}
