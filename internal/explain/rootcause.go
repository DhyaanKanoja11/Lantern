package explain

import (
	"fmt"
	"strings"

	"lantern/internal/domain"
)

// RootCauseType categorizes the primary causal origin of service exposure.
type RootCauseType string

const (
	// RootCauseComposePublishedPort indicates exposure originated from a Docker Compose port declaration.
	RootCauseComposePublishedPort RootCauseType = "COMPOSE_PUBLISHED_PORT"
	// RootCauseDockerPublishedPort indicates exposure originated from a Docker published port without Compose evidence.
	RootCauseDockerPublishedPort RootCauseType = "DOCKER_PUBLISHED_PORT"
	// RootCauseProcessWildcardBind indicates exposure originated from a native process bound to a wildcard address.
	RootCauseProcessWildcardBind RootCauseType = "PROCESS_WILDCARD_BIND"
	// RootCauseProcessSpecificBind indicates exposure originated from a native process bound to a specific network interface.
	RootCauseProcessSpecificBind RootCauseType = "PROCESS_SPECIFIC_BIND"
	// RootCauseProcessLoopbackBind indicates a native process bound strictly to loopback (not exposed beyond localhost).
	RootCauseProcessLoopbackBind RootCauseType = "PROCESS_LOOPBACK_BIND"
	// RootCauseUnresolved indicates insufficient evidence exists to establish a definitive root cause.
	RootCauseUnresolved RootCauseType = "UNRESOLVED"
)

// RootCause encapsulates the deterministic causal classification of an exposed service.
type RootCause struct {
	Type        RootCauseType `json:"type"`
	Description string        `json:"description"`
	Source      string        `json:"source"`
	Certain     bool          `json:"certain"`
	File        string        `json:"file,omitempty"`
	Line        int           `json:"line,omitempty"`
	Detail      string        `json:"detail,omitempty"`
}

// ClassifyRootCause deterministically establishes the root cause from correlated domain evidence.
// Precedence:
// 1. Docker Compose configuration evidence (when correlated with Docker runtime port mapping)
// 2. Docker container runtime published port (when no Compose evidence exists)
// 3. Native process / socket bind evidence (loopback, wildcard, or specific interface)
// 4. Unresolved (insufficient evidence)
func ClassifyRootCause(
	listener domain.Listener,
	proc *domain.Process,
	container *domain.Container,
	mapping *domain.PortMapping,
	config *domain.ConfigEvidence,
	reach domain.Reachability,
) RootCause {
	if listener.Port == 0 {
		return RootCause{
			Type:        RootCauseUnresolved,
			Description: "Insufficient evidence: invalid or missing listener port",
			Source:      "unknown",
			Certain:     false,
			Detail:      "No active listener socket provided",
		}
	}

	cleanListenAddr := strings.Trim(strings.TrimSpace(listener.Address), "[]")

	// 1. Docker Container Attribution
	if container != nil {
		cleanHostIP := ""
		if mapping != nil {
			cleanHostIP = strings.Trim(strings.TrimSpace(mapping.HostIP), "[]")
		}
		addrCompatible := mapping != nil && (isWildcardAddress(cleanHostIP) || isWildcardAddress(cleanListenAddr) || cleanHostIP == cleanListenAddr)

		// Case 1A & 1B: Container has an observed published port mapping matching this listener
		if mapping != nil && mapping.HostPort == listener.Port && addrCompatible {
			// Case A: Correlated Docker Compose configuration evidence exists
			if config != nil && config.File != "" {
				// Verify Compose evidence corresponds to observed Docker mapping
				portMatches := (config.HostPort == mapping.HostPort) ||
					(config.HostPort == 0 && config.ContainerPort == mapping.ContainerPort)

				if portMatches && config.ContainerPort > 0 && mapping.ContainerPort > 0 {
					portMatches = (config.ContainerPort == mapping.ContainerPort)
				}

				if portMatches && config.Protocol != "" && mapping.Protocol != "" {
					portMatches = strings.EqualFold(config.Protocol, mapping.Protocol)
				}

				if portMatches && config.HostIP != "" && mapping.HostIP != "" {
					cfgIP := strings.Trim(strings.TrimSpace(config.HostIP), "[]")
					mapIP := strings.Trim(strings.TrimSpace(mapping.HostIP), "[]")

					if cfgIP != mapIP && !(isWildcardAddress(cfgIP) && isWildcardAddress(mapIP)) {
						portMatches = false
					}
				}

				if portMatches {
					desc := fmt.Sprintf("Docker Compose published host port %d", listener.Port)
					if config.Service != "" {
						desc = fmt.Sprintf("Docker Compose published host port %d for service %q", listener.Port, config.Service)
					}
					source := config.File
					if config.Line > 0 {
						source = fmt.Sprintf("%s:%d", config.File, config.Line)
					}
					detail := config.Original
					if detail == "" {
						detail = config.Evidence
					}

					return RootCause{
						Type:        RootCauseComposePublishedPort,
						Description: desc,
						Source:      source,
						Certain:     config.Certain,
						File:        config.File,
						Line:        config.Line,
						Detail:      detail,
					}
				}

				// Mismatched Compose configuration: Compose evidence does not explain this host port
				return RootCause{
					Type:        RootCauseDockerPublishedPort,
					Description: fmt.Sprintf("Docker container %q published host port %d (Compose config mismatch)", container.Name, listener.Port),
					Source:      fmt.Sprintf("docker container %s", container.Name),
					Certain:     false,
					Detail:      fmt.Sprintf("Compose declaration %q does not match observed mapping %s:%d", config.Evidence, mapping.HostIP, mapping.HostPort),
				}
			}

			// Case B: Docker published port without Compose evidence
			cName := container.Name
			if cName == "" {
				cName = container.ID
			}
			return RootCause{
				Type:        RootCauseDockerPublishedPort,
				Description: fmt.Sprintf("Docker container %q published host port %d without Compose configuration", cName, listener.Port),
				Source:      fmt.Sprintf("docker container %s", cName),
				Certain:     true,
				Detail:      fmt.Sprintf("Container port %d published to host %s:%d (%s)", mapping.ContainerPort, mapping.HostIP, mapping.HostPort, mapping.Protocol),
			}
		}

		// Container present, but published port mapping does not match or is absent.
		// Only infer host-networking container ownership when PID correlation is established!
		hasHostPIDMatch := container.HostPID > 0 &&
			(listener.PID == container.HostPID ||
				(proc != nil && proc.PID == container.HostPID))

		if hasHostPIDMatch {
			cName := container.Name
			if cName == "" {
				cName = container.ID
			}

			if isLoopbackAddress(cleanListenAddr) || reach.State == "LOOPBACK_ONLY" {
				return RootCause{
					Type:        RootCauseProcessLoopbackBind,
					Description: fmt.Sprintf("Container %q process bound to loopback address %s", cName, listener.Address),
					Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
					Certain:     true,
					Detail:      "Host networking: container process bound strictly to loopback",
				}
			}
			if isWildcardAddress(cleanListenAddr) {
				return RootCause{
					Type:        RootCauseProcessWildcardBind,
					Description: fmt.Sprintf("Container %q process bound to wildcard address %s (host networking)", cName, listener.Address),
					Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
					Certain:     true,
					Detail:      fmt.Sprintf("Host networking: container process bound to all host interfaces (%s)", reach.State),
				}
			}
			if cleanListenAddr != "" {
				return RootCause{
					Type:        RootCauseProcessSpecificBind,
					Description: fmt.Sprintf("Container %q process bound to specific address %s (host networking)", cName, listener.Address),
					Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
					Certain:     true,
					Detail:      fmt.Sprintf("Host networking: container process bound to specific interface (%s)", reach.State),
				}
			}
		}
		// If !hasHostPIDMatch: do NOT claim host-networking.
		// Fall through to native process attribution / unresolved!
	}

	// 2. Native Process Attribution
	procName := "process"
	hasProc := false
	if proc != nil && (proc.Name != "" || proc.PID > 0) {
		hasProc = true
		if proc.Name != "" {
			procName = proc.Name
		} else {
			procName = fmt.Sprintf("PID %d", proc.PID)
		}
	}

	// Case H: Insufficient evidence when process attribution is unavailable
	if !hasProc {
		return RootCause{
			Type:        RootCauseUnresolved,
			Description: "Insufficient evidence to determine root cause",
			Source:      "unknown",
			Certain:     false,
			Detail:      fmt.Sprintf("Listener on %s:%d detected, but process, container, and configuration attribution are unavailable", listener.Address, listener.Port),
		}
	}

	// Case C: Loopback bind
	if (isLoopbackAddress(cleanListenAddr) || reach.State == "LOOPBACK_ONLY") && !isWildcardAddress(cleanListenAddr) {
		return RootCause{
			Type:        RootCauseProcessLoopbackBind,
			Description: fmt.Sprintf("Service %q explicitly bound to loopback interface only", procName),
			Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
			Certain:     true,
			Detail:      "Localhost only; not accessible from external networks",
		}
	}

	// Case D: Wildcard bind
	if isWildcardAddress(cleanListenAddr) {
		return RootCause{
			Type:        RootCauseProcessWildcardBind,
			Description: fmt.Sprintf("Process %q bound to wildcard address %s", procName, listener.Address),
			Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
			Certain:     hasProc,
			Detail:      fmt.Sprintf("Wildcard socket binding makes service reachable on all active interfaces (%s)", reach.State),
		}
	}

	// Case E: Specific address bind
	if cleanListenAddr != "" && cleanListenAddr != "unknown" {
		return RootCause{
			Type:        RootCauseProcessSpecificBind,
			Description: fmt.Sprintf("Process %q explicitly bound to specific address %s", procName, listener.Address),
			Source:      fmt.Sprintf("%s:%d", listener.Address, listener.Port),
			Certain:     hasProc,
			Detail:      fmt.Sprintf("Bound to specific local network interface (%s)", reach.State),
		}
	}

	// Case H: Insufficient evidence (Unresolved)
	return RootCause{
		Type:        RootCauseUnresolved,
		Description: "Insufficient evidence to determine root cause",
		Source:      "unknown",
		Certain:     false,
		Detail:      "Listening socket detected but process, container, or configuration attribution is unavailable",
	}
}

func isLoopbackAddress(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || strings.HasPrefix(addr, "127.")
}

func isWildcardAddress(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "*" || addr == ""
}
