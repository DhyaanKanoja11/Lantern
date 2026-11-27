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
	"github.com/DhyaanKanoja11/Lantern/internal/remediation"
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

// Reallocation represents a single port rewrite from old host port to new host port.
type Reallocation struct {
	File    string `json:"file"`
	Service string `json:"service"`
	Line    int    `json:"line"`
	OldPort uint16 `json:"old_port"`
	NewPort uint16 `json:"new_port"`
}

// ReallocationOutcome holds the result of executing port reallocation.
type ReallocationOutcome struct {
	Reallocations []Reallocation    `json:"reallocations"`
	Diff          string            `json:"diff,omitempty"`
	Backups       map[string]string `json:"backups,omitempty"`
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

// Reallocate automatically rewrites colliding ports in Compose file(s) to free ports.
// If dryRun is true, it returns the unified diff and modifies nothing.
// If dryRun is false, it uses the safe write path (fingerprint, backup, atomic write, AST verification).
func (c *Checker) Reallocate(ctx context.Context, report *Report, dryRun bool) (*ReallocationOutcome, error) {
	if report == nil || len(report.Collisions) == 0 {
		return &ReallocationOutcome{}, nil
	}

	// 1. Gather all currently used ports to guarantee distinct port selection
	usedPorts := make(map[uint16]bool)

	// Collect host listeners
	var listeners []domain.Listener
	if c.collector != nil {
		listeners, _ = c.collector.CollectListeners(ctx)
	}
	listenerMap := make(map[uint16]domain.Listener, len(listeners))
	for _, l := range listeners {
		listenerMap[l.Port] = l
		usedPorts[l.Port] = true
	}

	// Collect all non-colliding declared ports from the audited files
	collidingKeys := make(map[string]bool)
	for _, col := range report.Collisions {
		collidingKeys[fmt.Sprintf("%s:%d", col.Service, col.Line)] = true
	}

	for _, filePath := range report.Files {
		data, err := os.ReadFile(filePath)
		if err == nil {
			if evList, err := compose.ParseComposeFile(filePath, data); err == nil {
				for _, ev := range evList {
					key := fmt.Sprintf("%s:%d", ev.Service, ev.Line)
					if !collidingKeys[key] && !ev.Port.IsEphemeral() {
						usedPorts[ev.Port.HostPortStart] = true
					}
				}
			}
		}
	}

	// 2. Allocate distinct free ports for each collision
	var reallocations []Reallocation
	for _, col := range report.Collisions {
		targetFile := col.File
		if targetFile == "" {
			targetFile = report.FilePath
		}

		candidate := col.SuggestedPort
		if candidate == 0 || usedPorts[candidate] {
			candidate = c.findNextAvailablePort(col.Port, listenerMap, claimedPortsToNames(usedPorts))
		}
		for candidate > 0 && candidate < 65535 && usedPorts[candidate] {
			candidate = c.findNextAvailablePort(candidate, listenerMap, claimedPortsToNames(usedPorts))
		}

		if candidate == 0 || candidate > 65535 {
			return nil, fmt.Errorf("failed to allocate unique free port for service %q (port %d)", col.Service, col.Port)
		}

		usedPorts[candidate] = true
		reallocations = append(reallocations, Reallocation{
			File:    targetFile,
			Service: col.Service,
			Line:    col.Line,
			OldPort: col.Port,
			NewPort: candidate,
		})
	}

	// 3. Group reallocations by file and perform modifications in memory
	var fileOrder []string
	reallocsByFile := make(map[string][]Reallocation)
	for _, r := range reallocations {
		if _, exists := reallocsByFile[r.File]; !exists {
			fileOrder = append(fileOrder, r.File)
		}
		reallocsByFile[r.File] = append(reallocsByFile[r.File], r)
	}

	type fileMod struct {
		filePath  string
		origBytes []byte
		modBytes  []byte
		fi        os.FileInfo
	}
	var fileMods []fileMod

	for _, filePath := range fileOrder {
		rList := reallocsByFile[filePath]
		fi, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("cannot stat compose file %s: %w", filePath, err)
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("compose path %s is a directory", filePath)
		}

		origBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("cannot read compose file %s: %w", filePath, err)
		}

		fp := remediation.ComputeBytesFingerprint(filePath, fi.Size(), origBytes)
		if err := remediation.VerifyFingerprint(filePath, fp); err != nil {
			return nil, fmt.Errorf("file integrity check failed for %s: %w", filePath, err)
		}

		currBytes := origBytes
		for _, realloc := range rList {
			currBytes, err = remediation.ModifyComposeHostPortBytes(currBytes, filePath, realloc.Service, realloc.Line, realloc.OldPort, realloc.NewPort)
			if err != nil {
				return nil, fmt.Errorf("reallocation failed for service %q in %s: %w", realloc.Service, filePath, err)
			}
		}

		fileMods = append(fileMods, fileMod{
			filePath:  filePath,
			origBytes: origBytes,
			modBytes:  currBytes,
			fi:        fi,
		})
	}

	// 4. If dry-run, generate unified diff and return without touching disk
	if dryRun {
		var diffBuilder strings.Builder
		for _, fm := range fileMods {
			d := formatUnifiedDiff(fm.filePath, fm.origBytes, fm.modBytes)
			diffBuilder.WriteString(d)
		}
		return &ReallocationOutcome{
			Reallocations: reallocations,
			Diff:          diffBuilder.String(),
		}, nil
	}

	// 5. Live application: create backups and write atomically
	backups := make(map[string]string)
	for _, fm := range fileMods {
		backupPath, err := remediation.CreateBackupFromBytes(fm.filePath, fm.origBytes, fm.fi)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup for %s: %w", fm.filePath, err)
		}
		backups[fm.filePath] = backupPath

		perm := fm.fi.Mode().Perm()
		if perm == 0 {
			perm = 0644
		}
		if err := remediation.AtomicWrite(fm.filePath, fm.modBytes, perm); err != nil {
			return nil, fmt.Errorf("failed to atomically write reallocated file %s: %w", fm.filePath, err)
		}

		// Post-write AST verification
		if _, err := compose.ParseComposeFile(fm.filePath, fm.modBytes); err != nil {
			return nil, fmt.Errorf("post-write verification failed for %s: %w", fm.filePath, err)
		}
	}

	return &ReallocationOutcome{
		Reallocations: reallocations,
		Backups:       backups,
	}, nil
}

func formatUnifiedDiff(filePath string, origBytes, modBytes []byte) string {
	relPath := filepath.Base(filePath)
	origLines := splitLines(origBytes)
	modLines := splitLines(modBytes)

	if len(origLines) != len(modLines) {
		var b strings.Builder
		fmt.Fprintf(&b, "--- a/%s\n", relPath)
		fmt.Fprintf(&b, "+++ b/%s\n", relPath)
		for _, l := range origLines {
			fmt.Fprintf(&b, "-%s\n", l)
		}
		for _, l := range modLines {
			fmt.Fprintf(&b, "+%s\n", l)
		}
		return b.String()
	}

	var changed []int
	for i := range origLines {
		if origLines[i] != modLines[i] {
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", relPath)
	fmt.Fprintf(&b, "+++ b/%s\n", relPath)

	hunkStart := -1
	hunkEnd := -1

	for _, idx := range changed {
		s := idx - 3
		if s < 0 {
			s = 0
		}
		e := idx + 1 + 3
		if e > len(origLines) {
			e = len(origLines)
		}

		if hunkStart == -1 {
			hunkStart = s
			hunkEnd = e
		} else if s <= hunkEnd {
			hunkEnd = e
		} else {
			renderHunk(&b, origLines, modLines, hunkStart, hunkEnd)
			hunkStart = s
			hunkEnd = e
		}
	}
	if hunkStart != -1 {
		renderHunk(&b, origLines, modLines, hunkStart, hunkEnd)
	}

	return b.String()
}

func renderHunk(b *strings.Builder, origLines, modLines []string, start, end int) {
	origHunkCount := 0
	modHunkCount := 0
	for i := start; i < end; i++ {
		if origLines[i] == modLines[i] {
			origHunkCount++
			modHunkCount++
		} else {
			origHunkCount++
			modHunkCount++
		}
	}
	fmt.Fprintf(b, "@@ -%d,%d +%d,%d @@\n", start+1, origHunkCount, start+1, modHunkCount)
	for i := start; i < end; i++ {
		if origLines[i] == modLines[i] {
			fmt.Fprintf(b, " %s\n", origLines[i])
		} else {
			fmt.Fprintf(b, "-%s\n", origLines[i])
			fmt.Fprintf(b, "+%s\n", modLines[i])
		}
	}
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := strings.TrimRight(string(data), "\r\n")
	raw := strings.Split(s, "\n")
	for i := range raw {
		raw[i] = strings.TrimRight(raw[i], "\r")
	}
	return raw
}
