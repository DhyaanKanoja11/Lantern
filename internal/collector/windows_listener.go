//go:build windows

package collector

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

type windowsCommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type windowsCollector struct {
	runner windowsCommandRunner
}

func defaultWindowsExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func newPlatformCollector() ListenerCollector {
	return newWindowsCollector()
}

func newWindowsCollector() *windowsCollector {
	return newWindowsCollectorWithRunner(defaultWindowsExecRunner)
}

func newWindowsCollectorWithRunner(runner windowsCommandRunner) *windowsCollector {
	return &windowsCollector{runner: runner}
}

func (c *windowsCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	out, err := c.runner(ctx, "netstat", "-ano")
	if err != nil {
		return nil, fmt.Errorf("failed to execute netstat on Windows: %w", err)
	}

	return ParseWindowsNetstat(bytes.NewReader(out))
}

func (c *windowsCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
	listeners, err := c.CollectListeners(ctx)
	if err != nil {
		return nil, err
	}

	match := findMostExposedOnPort(listeners, port)
	if match == nil {
		return nil, fmt.Errorf("no listener found for port %d", port)
	}

	return match, nil
}
