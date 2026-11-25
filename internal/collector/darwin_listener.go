//go:build darwin

package collector

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

type darwinCommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type darwinCollector struct {
	runner darwinCommandRunner
}

func defaultDarwinExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func newPlatformCollector() ListenerCollector {
	return newDarwinCollector()
}

func newDarwinCollector() *darwinCollector {
	return newDarwinCollectorWithRunner(defaultDarwinExecRunner)
}

func newDarwinCollectorWithRunner(runner darwinCommandRunner) *darwinCollector {
	return &darwinCollector{runner: runner}
}

func (c *darwinCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	out, err := c.runner(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n")
	if err != nil {
		return nil, fmt.Errorf("failed to discover listeners via lsof on macOS: %w", err)
	}

	return ParseDarwinLsof(bytes.NewReader(out))
}

func (c *darwinCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
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
