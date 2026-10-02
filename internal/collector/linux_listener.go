//go:build linux

package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"lantern/internal/domain"
)

type linuxCollector struct{}

func newPlatformCollector() ListenerCollector {
	return &linuxCollector{}
}

// CollectListeners implements ListenerCollector on Linux.
func (c *linuxCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	// Attempt primary source: ss -lntpH
	listeners, ssErr := c.collectFromSS(ctx)
	if ssErr == nil && len(listeners) > 0 {
		return listeners, nil
	}

	// Fallback to /proc/net/tcp and /proc/net/tcp6
	procListeners, procErr := c.collectFromProc()
	if procErr == nil && len(procListeners) > 0 {
		return procListeners, nil
	}

	// If SS succeeded but returned 0 listeners, return empty list
	if ssErr == nil {
		return listeners, nil
	}

	// Both failed
	return nil, fmt.Errorf("failed to discover listeners (ss error: %v, proc error: %v)", ssErr, procErr)
}

func (c *linuxCollector) collectFromSS(ctx context.Context) ([]domain.Listener, error) {
	cmd := exec.CommandContext(ctx, "ss", "-lntpH")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ss command failed: %w (stderr: %s)", err, stderr.String())
	}

	return ParseSSOutput(&stdout)
}

func (c *linuxCollector) collectFromProc() ([]domain.Listener, error) {
	var allListeners []domain.Listener

	// Read IPv4 /proc/net/tcp
	if data, err := os.Open("/proc/net/tcp"); err == nil {
		defer data.Close()
		if l, err := ParseProcNetTCP(data); err == nil {
			allListeners = append(allListeners, l...)
		}
	}

	// Read IPv6 /proc/net/tcp6
	if data6, err := os.Open("/proc/net/tcp6"); err == nil {
		defer data6.Close()
		if l6, err := ParseProcNetTCP6(data6); err == nil {
			allListeners = append(allListeners, l6...)
		}
	}

	if len(allListeners) == 0 {
		return nil, fmt.Errorf("/proc/net/tcp and /proc/net/tcp6 produced no listeners or were unreadable")
	}

	return DeduplicateAndSort(allListeners), nil
}

// FindListenerByPort searches for a listener on a specific port.
func (c *linuxCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
	listeners, err := c.CollectListeners(ctx)
	if err != nil {
		return nil, err
	}

	var match *domain.Listener
	for i := range listeners {
		if listeners[i].Port == port {
			// If we haven't found a match yet, take this one
			if match == nil {
				match = &listeners[i]
				continue
			}
			// Prefer non-loopback / wildcard address over 127.0.0.1
			if match.Address == "127.0.0.1" && listeners[i].Address != "127.0.0.1" {
				match = &listeners[i]
			}
		}
	}

	if match == nil {
		return nil, fmt.Errorf("no listener found for port %d", port)
	}

	return match, nil
}
