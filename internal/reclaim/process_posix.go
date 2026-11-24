//go:build !windows

package reclaim

import (
	"os"
	"syscall"
	"time"
)

// defaultProcessKiller terminates a process by PID on POSIX systems.
func defaultProcessKiller(pid int, force bool, gracePeriod time.Duration) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if force {
		return proc.Kill()
	}

	// Attempt graceful SIGTERM first
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return proc.Kill()
	}

	// Poll briefly for process exit
	deadline := time.Now().Add(gracePeriod)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		// Signal(0) verifies if process still exists
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
	}

	// Grace period expired without exit; escalate to SIGKILL
	return proc.Kill()
}
