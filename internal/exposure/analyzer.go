package exposure

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"lantern/internal/collector"
	"lantern/internal/compose"
	"lantern/internal/docker"
	"lantern/internal/domain"
	"lantern/internal/explain"
	"lantern/internal/network"
	"lantern/internal/process"
)

var (
	// ErrNoListener indicates no active listening socket was found on the requested port.
	ErrNoListener = errors.New("no listening service found")
	// ErrAmbiguousListener indicates multiple conflicting listeners were found on the requested port.
	ErrAmbiguousListener = errors.New("ambiguous listener: multiple listeners found on requested port")
)

// DefaultAnalyzer orchestrates discovery, attribution, and reachability analysis.
type DefaultAnalyzer struct {
	collector collector.ListenerCollector
	inspector process.ProcessInspector
	docker    docker.DockerCorrelator
	compose   compose.ComposeResolver
	network   network.InterfaceClassifier
	explainer explain.Explainer
}

// NewDefaultAnalyzer creates an Analyzer with default production dependencies.
func NewDefaultAnalyzer() *DefaultAnalyzer {
	return &DefaultAnalyzer{
		collector: collector.NewDefaultCollector(),
		inspector: process.NewDefaultInspector(),
		docker:    docker.NewDefaultCorrelator(),
		compose:   compose.NewDefaultResolver(),
		network:   network.NewDefaultClassifier(),
		explainer: explain.NewDefaultExplainer(),
	}
}

// NewAnalyzerWithDeps creates an Analyzer with explicit dependencies for testing.
func NewAnalyzerWithDeps(
	col collector.ListenerCollector,
	insp process.ProcessInspector,
	doc docker.DockerCorrelator,
	comp compose.ComposeResolver,
	net network.InterfaceClassifier,
	exp explain.Explainer,
) *DefaultAnalyzer {
	return &DefaultAnalyzer{
		collector: col,
		inspector: insp,
		docker:    doc,
		compose:   comp,
		network:   net,
		explainer: exp,
	}
}

// Why investigates the exposure path and causal origin for a specific TCP port.
func (a *DefaultAnalyzer) Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error) {
	if a.collector == nil {
		return nil, errors.New("listener collector unavailable")
	}

	listeners, err := a.collector.CollectListeners(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect listening sockets: %w", err)
	}

	var matched []domain.Listener
	for _, l := range listeners {
		if l.Port == port {
			matched = append(matched, l)
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w on port %d", ErrNoListener, port)
	}

	if isAmbiguousListeners(matched) {
		var addrs []string
		for _, m := range matched {
			addrs = append(addrs, fmt.Sprintf("%s (PID %d)", m.Address, m.PID))
		}
		return nil, fmt.Errorf("%w on port %d across addresses: %s", ErrAmbiguousListener, port, strings.Join(addrs, ", "))
	}

	targetListener := selectTargetListener(matched)

	// Process inspection
	var proc *domain.Process
	if targetListener.PID > 0 && a.inspector != nil {
		if p, err := a.inspector.Inspect(ctx, targetListener.PID); err == nil && p != nil {
			proc = p
		}
	}

	// Docker correlation
	var container *domain.Container
	var mapping *domain.PortMapping
	if a.docker != nil {
		if c, m, err := a.docker.CorrelateListener(ctx, targetListener); err == nil && c != nil {
			container = c
			mapping = m
		}
	}

	// Compose resolution
	var configEvidence *domain.ConfigEvidence
	if container != nil && a.compose != nil {
		if ce, err := a.compose.ResolveAttribution(ctx, container, port); err == nil && ce != nil {
			configEvidence = ce
		}
	}

	// Network reachability assessment
	var reach domain.Reachability
	var ifaces []domain.NetworkInterface
	if a.network != nil {
		r, infs, err := a.network.Assess(ctx, targetListener.Address)
		if err == nil {
			reach = r
			ifaces = infs
		}
	}

	proto := targetListener.Protocol
	if proto == "" {
		proto = "tcp"
	}

	exp := &domain.Exposure{
		Port:          port,
		Protocol:      proto,
		BindAddress:   targetListener.Address,
		Listener:      targetListener,
		Process:       proc,
		Container:     container,
		DockerMapping: mapping,
		Config:        configEvidence,
		Interfaces:    ifaces,
		Reachability:  reach,
	}

	// Recommendation generation
	rc := explain.ClassifyRootCause(targetListener, proc, container, mapping, configEvidence, reach)
	exp.Recommendation = GenerateRecommendation(exp, rc)

	return exp, nil
}

// Scan discovers all listening services and enriches them with process, container, and reachability metadata.
func (a *DefaultAnalyzer) Scan(ctx context.Context) ([]domain.ExposureSummary, error) {
	if a.collector == nil {
		return nil, errors.New("listener collector unavailable")
	}

	listeners, err := a.collector.CollectListeners(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect listening sockets: %w", err)
	}

	if len(listeners) == 0 {
		return nil, nil
	}

	var ifaces []domain.NetworkInterface
	if a.network != nil {
		if infs, err := a.network.DiscoverInterfaces(ctx); err == nil {
			ifaces = infs
		}
	}

	var summaries []domain.ExposureSummary
	for _, l := range listeners {
		var proc *domain.Process
		if l.PID > 0 && a.inspector != nil {
			if p, err := a.inspector.Inspect(ctx, l.PID); err == nil && p != nil {
				proc = p
			}
		}

		procName := "unknown"
		if proc != nil && proc.Name != "" {
			procName = proc.Name
		} else if l.ProcessName != "" {
			procName = l.ProcessName
		}

		var container *domain.Container
		if a.docker != nil {
			if c, _, err := a.docker.CorrelateListener(ctx, l); err == nil && c != nil {
				container = c
			}
		}

		containerName := "-"
		targetType := "native"
		if container != nil && container.Name != "" {
			containerName = container.Name
			targetType = "Docker"
		} else if proc == nil && l.PID == 0 {
			targetType = "-"
		}

		reachStr := "unknown"
		if a.network != nil {
			r := a.network.ClassifyReachability(l.Address, ifaces)
			reachStr = formatScanReachability(r)
		}

		summaries = append(summaries, domain.ExposureSummary{
			Port:          l.Port,
			Protocol:      l.Protocol,
			Address:       l.Address,
			ProcessName:   procName,
			PID:           l.PID,
			ContainerName: containerName,
			TargetType:    targetType,
			Reachability:  reachStr,
		})
	}

	return summaries, nil
}

func isAmbiguousListeners(listeners []domain.Listener) bool {
	if len(listeners) <= 1 {
		return false
	}
	firstAddr := listeners[0].Address
	firstPID := listeners[0].PID
	for _, l := range listeners[1:] {
		// Conflicting if distinct address and distinct PID
		if l.Address != firstAddr && firstPID > 0 && l.PID > 0 && l.PID != firstPID {
			return true
		}
	}
	return false
}

func selectTargetListener(listeners []domain.Listener) domain.Listener {
	if len(listeners) == 1 {
		return listeners[0]
	}
	// Prefer IPv4 or non-loopback if available
	for _, l := range listeners {
		if !strings.HasPrefix(l.Address, "::") && l.Address != "::1" {
			return l
		}
	}
	return listeners[0]
}

func formatScanReachability(reach domain.Reachability) string {
	switch reach.State {
	case "LOOPBACK_ONLY":
		return "localhost only"
	case "LAN_REACHABLE":
		return "LAN reachable"
	case "VPN_REACHABLE":
		return "VPN reachable"
	case "MULTI_INTERFACE":
		return "multi-interface"
	case "UNRESOLVED":
		return "unresolved"
	default:
		if reach.LAN == "yes" || reach.LAN == "possible" {
			return "LAN reachable"
		}
		if reach.Local {
			return "localhost only"
		}
		return "unknown"
	}
}
