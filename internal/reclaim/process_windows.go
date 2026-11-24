//go:build windows

package reclaim

import (
	"os"
	"time"
)

// defaultProcessKiller terminates a process by PID on Windows.
func defaultProcessKiller(pid int, force bool, gracePeriod time.Duration) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
