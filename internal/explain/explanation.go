package explain

import (
	"fmt"

	"lantern/internal/domain"
)

// Explanation provides the complete, deterministic causal explanation of service exposure.
type Explanation struct {
	Port          uint16                    `json:"port"`
	Protocol      string                    `json:"protocol"`
	BindAddress   string                    `json:"bind_address"`
	Listener      domain.Listener           `json:"listener"`
	Process       *domain.Process           `json:"process,omitempty"`
	Container     *domain.Container         `json:"container,omitempty"`
	DockerMapping *domain.PortMapping       `json:"docker_mapping,omitempty"`
	Config        *domain.ConfigEvidence    `json:"config,omitempty"`
	Interfaces    []domain.NetworkInterface `json:"interfaces,omitempty"`
	Reachability  domain.Reachability       `json:"reachability"`
	RootCause     RootCause                 `json:"root_cause"`
	Path          []PathNode                `json:"path"`
	Summary       string                    `json:"summary"`
}

// Explain analyzes an Exposure aggregate and constructs a deterministic Explanation.
func Explain(exp *domain.Exposure) *Explanation {
	if exp == nil {
		return nil
	}

	port := exp.Port
	if port == 0 {
		port = exp.Listener.Port
	}
	proto := exp.Protocol
	if proto == "" {
		proto = exp.Listener.Protocol
	}
	if proto == "" {
		proto = "tcp"
	}
	bindAddr := exp.BindAddress
	if bindAddr == "" {
		bindAddr = exp.Listener.Address
	}

	rc := ClassifyRootCause(exp.Listener, exp.Process, exp.Container, exp.DockerMapping, exp.Config, exp.Reachability)
	path := BuildExposurePath(exp, rc)
	summary := buildSummary(exp, rc, port, bindAddr)

	return &Explanation{
		Port:          port,
		Protocol:      proto,
		BindAddress:   bindAddr,
		Listener:      exp.Listener,
		Process:       exp.Process,
		Container:     exp.Container,
		DockerMapping: exp.DockerMapping,
		Config:        exp.Config,
		Interfaces:    exp.Interfaces,
		Reachability:  exp.Reachability,
		RootCause:     rc,
		Path:          path,
		Summary:       summary,
	}
}

func buildSummary(exp *domain.Exposure, rc RootCause, port uint16, bindAddr string) string {
	reachStr := formatReachability(exp.Reachability)

	switch rc.Type {
	case RootCauseComposePublishedPort:
		return fmt.Sprintf("Service is exposed on port %d via Docker Compose (%s). Reachability: %s.", port, rc.Source, reachStr)

	case RootCauseDockerPublishedPort:
		cName := "container"
		if exp.Container != nil && exp.Container.Name != "" {
			cName = exp.Container.Name
		}
		if !rc.Certain {
			return fmt.Sprintf("Service is exposed on port %d via Docker container %q port publishing (uncertain configuration attribution). Reachability: %s.", port, cName, reachStr)
		}
		return fmt.Sprintf("Service is exposed on port %d via Docker container %q port publishing. Reachability: %s.", port, cName, reachStr)

	case RootCauseProcessLoopbackBind:
		return fmt.Sprintf("Service is bound strictly to loopback address %s:%d. Not reachable from external networks.", bindAddr, port)

	case RootCauseProcessWildcardBind:
		procDesc := "Service"
		if exp.Process != nil && exp.Process.Name != "" {
			procDesc = fmt.Sprintf("Process %q", exp.Process.Name)
		}
		return fmt.Sprintf("%s is bound to wildcard address %s:%d, making it reachable on active local interfaces (%s). External reachability depends on network routing and firewall rules.", procDesc, bindAddr, port, reachStr)

	case RootCauseProcessSpecificBind:
		procDesc := "Service"
		if exp.Process != nil && exp.Process.Name != "" {
			procDesc = fmt.Sprintf("Process %q", exp.Process.Name)
		}
		return fmt.Sprintf("%s is bound to specific interface address %s:%d (%s).", procDesc, bindAddr, port, reachStr)

	case RootCauseUnresolved:
		fallthrough
	default:
		return fmt.Sprintf("Service listening on %s:%d, but root-cause evidence is unresolved.", bindAddr, port)
	}
}
