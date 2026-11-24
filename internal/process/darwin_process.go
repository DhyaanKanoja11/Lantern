//go:build darwin

package process

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type darwinInspector struct {
	runner commandRunner
}

func defaultExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func newPlatformInspector() ProcessInspector {
	return newDarwinInspector()
}

func newDarwinInspector() *darwinInspector {
	return newDarwinInspectorWithRunner(defaultExecRunner)
}

func newDarwinInspectorWithRunner(runner commandRunner) *darwinInspector {
	return &darwinInspector{runner: runner}
}

func (i *darwinInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID: %d", pid)
	}

	out, err := i.runner(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=,user=")
	if err != nil {
		return nil, fmt.Errorf("process %d not found or exited: %w", pid, err)
	}

	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	fields := strings.Fields(line)
	comm := fields[0]
	var user string
	if len(fields) > 1 {
		user = fields[len(fields)-1]
	}

	return &domain.Process{
		PID:  pid,
		Name: comm,
		User: user,
	}, nil
}

func (i *darwinInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return i.Inspect(ctx, pid)
}
