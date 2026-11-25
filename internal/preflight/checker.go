package preflight

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/collector"
	"github.com/DhyaanKanoja11/Lantern/internal/compose"
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/process"
)

// Collision describes an address or port clash detected before container startup.
type Collision struct {
	File          string `json:"file,omitempty"`
	Service       string `json:"service"`
	Line          int    `json:"line"`
	Port          uint16 `json:"port"`
	Kind          string `json:"kind"` // "HOST_COLLISION", "INTERNAL_DUPLICATE"
	OccupiedBy    string `json:"occupied_by"`
	SuggestedPort uint16 `json:"suggested_port,omitempty"`
}

// WildcardExposure describes a service binding to 0.0.0.0 or wildcard.
type WildcardExposure struct {
	File         string `json:"file,omitempty"`
	Service      string `json:"service"`
	Line         int    `json:"line"`
	Port         uint16 `json:"port"`
	Original     string `json:"original"`
	SuggestedFix string `json:"suggested_fix"`
}

// Report holds the complete preflight audit outcome.
type Report struct {
	FilePath   string             `json:"file_path"`
	Files      []string           `json:"files,omitempty"`
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

// DiscoverOverrideFiles returns the base Compose file along with a sibling
// override file (e.g. docker-compose.override.yml) in the same directory if present.
func DiscoverOverrideFiles(basePath string) []string {
	files := []string{basePath}
	baseName := filepath.Base(basePath)
	switch baseName {
	case "docker-compose.override.yml", "docker-compose.override.yaml", "compose.override.yml", "compose.override.yaml":
		return files
	}

	dir := filepath.Dir(basePath)
	var candidates []string
	if baseName == "compose.yml" || baseName == "compose.yaml" {
		candidates = []string{
			"compose.override.yaml",
			"compose.override.yml",
			"docker-compose.override.yaml",
			"docker-compose.override.yml",
		}
	} else {
		candidates = []string{
			"docker-compose.override.yml",
			"docker-compose.override.yaml",
			"compose.override.yml",
			"compose.override.yaml",
		}
	}

	cleanBase := filepath.Clean(basePath)
	for _, name := range candidates {
		cand := filepath.Clean(filepath.Join(dir, name))
		if cand == cleanBase {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			files = append(files, cand)
			break
		}
	}
	return files
}

// CheckFile runs preflight checks against a Docker Compose file, automatically
// including a sibling override file (e.g. docker-compose.override.yml) if present.
func (c *Checker) CheckFile(ctx context.Context, filePath string) (*Report, error) {
	files := DiscoverOverrideFiles(filePath)
	return c.CheckFiles(ctx, files...)
}

// CheckFiles runs preflight checks across one or more Docker Compose files,
// merging service port declarations before evaluating collisions and exposures.
func (c *Checker) CheckFiles(ctx context.Context, filePaths ...string) (*Report, error) {
	if len(filePaths) == 0 {
		return nil, fmt.Errorf("no compose files provided")
	}

	var perFileEvidence [][]compose.ExtractedEvidence
	for _, fp := range filePaths {
		data, err := os.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("failed to read compose file %s: %w", fp, err)
		}

		evidence, err := compose.ParseComposeFile(fp, data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse compose file %s: %w", fp, err)
		}
		perFileEvidence = append(perFileEvidence, evidence)
	}

	merged := mergeEvidence(perFileEvidence)
	report, err := c.CheckEvidence(ctx, filePaths[0], merged)
	if err != nil {
		return nil, err
	}
	report.Files = append([]string(nil), filePaths...)
	return report, nil
}

type portBindingKey struct {
	service       string
	hostIP        string
	hostPortStart uint16
	hostPortEnd   uint16
	containerPort uint16
	protocol      string
}

// mergeEvidence combines extracted port declarations across Compose files in order,
// deduplicating identical port mappings declared by the same service.
func mergeEvidence(perFile [][]compose.ExtractedEvidence) []compose.ExtractedEvidence {
	var merged []compose.ExtractedEvidence
	indexByKey := make(map[portBindingKey]int)

	for _, fileEv := range perFile {
		for _, ev := range fileEv {
			key := portBindingKey{
				service:       strings.ToLower(ev.Service),
				hostIP:        strings.Trim(strings.TrimSpace(ev.Port.HostIP), "[]"),
				hostPortStart: ev.Port.HostPortStart,
				hostPortEnd:   ev.Port.HostPortEnd,
				containerPort: ev.Port.ContainerPort,
				protocol:      strings.ToLower(ev.Port.Protocol),
			}
			if idx, exists := indexByKey[key]; exists {
				merged[idx] = ev
				continue
			}
			indexByKey[key] = len(merged)
			merged = append(merged, ev)
		}
	}

	return merged
}

// CheckEvidence evaluates extracted Compose declarations against host network state.
func (c *Checker) CheckEvidence(ctx context.Context, filePath string, evidence []compose.ExtractedEvidence) (*Report, error) {
	report := &Report{
		FilePath:   filePath,
		Files:      []string{filePath},
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

	type claimedEntry struct {
		service string
		file    string
	}

	// Track internal declarations to catch duplicate port declarations across Compose files
	claimedPorts := make(map[uint16]claimedEntry) // port -> first claiming service and file

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
				File:         ev.File,
				Service:      ev.Service,
				Line:         ev.Line,
				Port:         port,
				Original:     ev.Original,
				SuggestedFix: suggested,
			})
		}

		// B. Check for Internal Duplicate Collisions
		if existing, exists := claimedPorts[port]; exists {
			suggested := c.findNextAvailablePort(port, listenerMap, claimedPortsToNames(claimedPorts))
			occupiedBy := fmt.Sprintf("Service %q in same file", existing.service)
			if existing.file != "" && ev.File != "" && filepath.Clean(existing.file) != filepath.Clean(ev.File) {
				occupiedBy = fmt.Sprintf("Service %q in %s", existing.service, filepath.Base(existing.file))
			}
			report.Collisions = append(report.Collisions, Collision{
				File:          ev.File,
				Service:       ev.Service,
				Line:          ev.Line,
				Port:          port,
				Kind:          "INTERNAL_DUPLICATE",
				OccupiedBy:    occupiedBy,
				SuggestedPort: suggested,
			})
			report.Passed = false
			continue
		}
		claimedPorts[port] = claimedEntry{service: ev.Service, file: ev.File}

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

			suggested := c.findNextAvailablePort(port, listenerMap, claimedPortsToNames(claimedPorts))
			report.Collisions = append(report.Collisions, Collision{
				File:          ev.File,
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

func claimedPortsToNames[T any](m map[uint16]T) map[uint16]string {
	out := make(map[uint16]string, len(m))
	for k := range m {
		out[k] = ""
	}
	return out
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
