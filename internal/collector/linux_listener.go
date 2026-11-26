//go:build linux

package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
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
	cmd := exec.CommandContext(ctx, "ss", "-lntupH")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Fallback to -lntpH if -lntupH is unsupported
		stdout.Reset()
		stderr.Reset()
		cmdFallback := exec.CommandContext(ctx, "ss", "-lntpH")
		cmdFallback.Stdout = &stdout
		cmdFallback.Stderr = &stderr
		if errFallback := cmdFallback.Run(); errFallback != nil {
			return nil, fmt.Errorf("ss command failed: %w (stderr: %s)", err, stderr.String())
		}
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

	// Read IPv4 /proc/net/udp
	if dataUdp, err := os.Open("/proc/net/udp"); err == nil {
		defer dataUdp.Close()
		if lUdp, err := ParseProcNetUDP(dataUdp); err == nil {
			allListeners = append(allListeners, lUdp...)
		}
	}

	// Read IPv6 /proc/net/udp6
	if dataUdp6, err := os.Open("/proc/net/udp6"); err == nil {
		defer dataUdp6.Close()
		if lUdp6, err := ParseProcNetUDP6(dataUdp6); err == nil {
			allListeners = append(allListeners, lUdp6...)
		}
	}

	if len(allListeners) == 0 {
		return nil, fmt.Errorf("/proc/net/tcp, tcp6, udp, and udp6 produced no listeners or were unreadable")
	}

	return DeduplicateAndSort(allListeners), nil
}

// FindListenerByPort searches for a listener on a specific port.
func (c *linuxCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
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
