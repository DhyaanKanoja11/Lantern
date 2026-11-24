//go:build windows

package process

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type windowsInspector struct {
	runner commandRunner
}

func defaultExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func newPlatformInspector() ProcessInspector {
	return newWindowsInspector()
}

func newWindowsInspector() *windowsInspector {
	return newWindowsInspectorWithRunner(defaultExecRunner)
}

func newWindowsInspectorWithRunner(runner commandRunner) *windowsInspector {
	return &windowsInspector{runner: runner}
}

func (i *windowsInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID: %d", pid)
	}

	out, err := i.runner(ctx, "tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	if err != nil {
		return nil, fmt.Errorf("tasklist query failed for PID %d: %w", pid, err)
	}

	return ParseTasklistCSV(bytes.NewReader(out), pid)
}

func (i *windowsInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return i.Inspect(ctx, pid)
}
