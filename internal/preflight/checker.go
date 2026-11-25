package preflight

import (
	"context"
	"fmt"
	"os"

	"github.com/DhyaanKanoja11/Lantern/internal/collector"
	"github.com/DhyaanKanoja11/Lantern/internal/compose"
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/process"
)

// Collision describes an address or port clash detected before container startup.
type Collision struct {
	Service       string `json:"service"`
	Line          int    `json:"line"`
	Port          uint16 `json:"port"`
	Kind          string `json:"kind"` // "HOST_COLLISION", "INTERNAL_DUPLICATE"
	OccupiedBy    string `json:"occupied_by"`
	SuggestedPort uint16 `json:"suggested_port,omitempty"`
}

// WildcardExposure describes a service binding to 0.0.0.0 or wildcard.
type WildcardExposure struct {
	Service      string `json:"service"`
	Line         int    `json:"line"`
	Port         uint16 `json:"port"`
	Original     string `json:"original"`
	SuggestedFix string `json:"suggested_fix"`
}

// Report holds the complete preflight audit outcome.
type Report struct {
	FilePath   string             `json:"file_path"`
	TotalPorts int                `json:"total_ports"`
	Collisions []Collision        `json:"collisions"`
	Wildcards  []WildcardExposure `json:"wildcards"`
	Passed     bool               `json:"passed"`
}

// Checker coordinates preflight validation of Docker Compose files.
type Checker struct {
	collector collector.ListenerCollector
	inspector process.ProcessInspector
}

// NewChecker initializes a Preflight checker with default dependencies.
func NewChecker() *Checker {
	return &Checker{
		collector: collector.NewDefaultCollector(),
		inspector: process.NewDefaultInspector(),
	}
}

// NewCheckerWithDeps initializes a Preflight checker with explicit dependencies for hermetic testing.
func NewCheckerWithDeps(col collector.ListenerCollector, insp process.ProcessInspector) *Checker {
	return &Checker{
		collector: col,
		inspector: insp,
	}
}

// CheckFile runs preflight checks against a Docker Compose file.
func (c *Checker) CheckFile(ctx context.Context, filePath string) (*Report, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file: %w", err)
	}

	evidence, err := compose.ParseComposeFile(filePath, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse compose file: %w", err)
	}

	return c.CheckEvidence(ctx, filePath, evidence)
}

// CheckEvidence evaluates extracted Compose declarations against host network state.
func (c *Checker) CheckEvidence(ctx context.Context, filePath string, evidence []compose.ExtractedEvidence) (*Report, error) {
	report := &Report{
		FilePath:   filePath,
		TotalPorts: len(evidence),
		Collisions: []Collision{},
		Wildcards:  []WildcardExposure{},
		Passed:     true,
	}

	if len(evidence) == 0 {
		return report, nil
	}

	// 1. Collect live host listeners
	var listeners []domain.Listener
	if c.collector != nil {
		var err error
		listeners, err = c.collector.CollectListeners(ctx)
		if err != nil {
			// Non-fatal; continue with internal duplicate validation
			listeners = nil
		}
	}

	// Build listener lookup map: port -> listener
	listenerMap := make(map[uint16]domain.Listener, len(listeners))
	for _, l := range listeners {
		listenerMap[l.Port] = l
	}

	// Track internal declarations to catch duplicate port declarations within the same compose file
	claimedPorts := make(map[uint16]string) // port -> service name

	for _, ev := range evidence {
		if ev.Port.IsEphemeral() {
			continue
		}

		port := ev.Port.HostPortStart

		// A. Check for Wildcard Exposure
		hostIP := ev.Port.HostIP
		if hostIP == "" || hostIP == "0.0.0.0" || hostIP == "::" {
			suggested := fmt.Sprintf("127.0.0.1:%d:%d", port, ev.Port.ContainerPort)
			report.Wildcards = append(report.Wildcards, WildcardExposure{
				Service:      ev.Service,
				Line:         ev.Line,
				Port:         port,
				Original:     ev.Original,
				SuggestedFix: suggested,
			})
		}

		// B. Check for Internal Duplicate Collisions
		if existingService, exists := claimedPorts[port]; exists {
			suggested := c.findNextAvailablePort(port, listenerMap, claimedPorts)
			report.Collisions = append(report.Collisions, Collision{
				Service:       ev.Service,
				Line:          ev.Line,
				Port:          port,
				Kind:          "INTERNAL_DUPLICATE",
				OccupiedBy:    fmt.Sprintf("Service %q in same file", existingService),
				SuggestedPort: suggested,
			})
			report.Passed = false
			continue
		}
		claimedPorts[port] = ev.Service

		// C. Check for Host Listener Collisions
		if l, occupied := listenerMap[port]; occupied {
			report.Passed = false
			occupant := fmt.Sprintf("Host process on %s", l.Address)
			if l.PID > 0 {
				occupant = fmt.Sprintf("PID %d", l.PID)
				if c.inspector != nil {
					proc, err := c.inspector.Inspect(ctx, l.PID)
					if err == nil && proc != nil && proc.Name != "" {
						occupant = fmt.Sprintf("%s (PID %d)", proc.Name, l.PID)
					}
				}
			}

			suggested := c.findNextAvailablePort(port, listenerMap, claimedPorts)
			report.Collisions = append(report.Collisions, Collision{
				Service:       ev.Service,
				Line:          ev.Line,
				Port:          port,
				Kind:          "HOST_COLLISION",
				OccupiedBy:    occupant,
				SuggestedPort: suggested,
			})
		}
	}

	return report, nil
}

func (c *Checker) findNextAvailablePort(start uint16, listeners map[uint16]domain.Listener, claimed map[uint16]string) uint16 {
	candidate := start + 1
	for candidate < 65535 {
		if _, inListeners := listeners[candidate]; inListeners {
			candidate++
			continue
		}
		if _, inClaimed := claimed[candidate]; inClaimed {
			candidate++
			continue
		}
		return candidate
	}
	return 0
}
