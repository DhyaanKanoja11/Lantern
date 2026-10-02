package explain

import (
	"fmt"
	"path/filepath"
	"strings"

	"lantern/internal/domain"
)

// PathNode represents a single causal link in the exposure path.
type PathNode struct {
	Step        string `json:"step"`
	Description string `json:"description"`
	Detail      string `json:"detail,omitempty"`
}

// BuildExposurePath constructs the ordered causal sequence leading to service exposure.
// The sequence typically follows:
// Configuration -> Port Declaration -> Process/Container -> Socket -> Interface -> Reachability
// Compose configuration nodes are ONLY rendered when the final root cause is RootCauseComposePublishedPort.
func BuildExposurePath(exp *domain.Exposure, rc ...RootCause) []PathNode {
	if exp == nil || (exp.Port == 0 && exp.Listener.Port == 0) {
		return nil
	}

	var rootCause RootCause
	if len(rc) > 0 {
		rootCause = rc[0]
	} else {
		rootCause = ClassifyRootCause(exp.Listener, exp.Process, exp.Container, exp.DockerMapping, exp.Config, exp.Reachability)
	}

	var nodes []PathNode

	// 1. Configuration Evidence - ONLY render when Compose was classified as the root cause!
	if rootCause.Type == RootCauseComposePublishedPort && exp.Config != nil && exp.Config.File != "" {
		cfgName := filepath.Base(exp.Config.File)
		detail := fmt.Sprintf("File: %s:%d", exp.Config.File, exp.Config.Line)
		if exp.Config.Service != "" {
			detail = fmt.Sprintf("Service: %s in %s:%d", exp.Config.Service, exp.Config.File, exp.Config.Line)
		}
		nodes = append(nodes, PathNode{
			Step:        "Configuration",
			Description: cfgName,
			Detail:      detail,
		})

		// Port mapping declaration in Compose
		portDecl := exp.Config.Evidence
		if portDecl == "" && exp.Config.HostPort > 0 && exp.Config.ContainerPort > 0 {
			portDecl = fmt.Sprintf("%d:%d", exp.Config.HostPort, exp.Config.ContainerPort)
		}
		if portDecl != "" {
			nodes = append(nodes, PathNode{
				Step:        "Port Declaration",
				Description: portDecl,
				Detail:      fmt.Sprintf("Compose port mapping declaration: %s", portDecl),
			})
		}
	}

	// 2. Container or Process
	isContainerAttributed := rootCause.Type == RootCauseComposePublishedPort ||
		rootCause.Type == RootCauseDockerPublishedPort ||
		strings.Contains(rootCause.Description, "Container")

	if isContainerAttributed && exp.Container != nil {
		cName := exp.Container.Name
		if cName == "" {
			cName = exp.Container.ID
		}
		detail := fmt.Sprintf("Image: %s", exp.Container.Image)
		if exp.Container.ID != "" {
			detail += fmt.Sprintf(", ID: %s", exp.Container.ID)
		}
		nodes = append(nodes, PathNode{
			Step:        "Container",
			Description: fmt.Sprintf("Docker container: %s", cName),
			Detail:      detail,
		})

		// If no compose config (or rejected), but container has docker mapping, show published port mapping node
		if rootCause.Type == RootCauseDockerPublishedPort && exp.DockerMapping != nil {
			nodes = append(nodes, PathNode{
				Step:        "Port Mapping",
				Description: fmt.Sprintf("%s:%d -> %d/%s", exp.DockerMapping.HostIP, exp.DockerMapping.HostPort, exp.DockerMapping.ContainerPort, exp.DockerMapping.Protocol),
				Detail:      "Docker published port mapping",
			})
		}
	} else if exp.Process != nil && (exp.Process.Name != "" || exp.Process.PID > 0) {
		procDesc := exp.Process.Name
		if procDesc == "" {
			procDesc = fmt.Sprintf("PID %d", exp.Process.PID)
		} else if exp.Process.PID > 0 {
			procDesc = fmt.Sprintf("Process: %s (PID %d)", exp.Process.Name, exp.Process.PID)
		} else {
			procDesc = fmt.Sprintf("Process: %s", exp.Process.Name)
		}
		detail := exp.Process.Executable
		if exp.Process.CommandLine != "" {
			detail = exp.Process.CommandLine
		}
		nodes = append(nodes, PathNode{
			Step:        "Process",
			Description: procDesc,
			Detail:      detail,
		})
	}

	// 3. Listening Socket
	bindAddr := exp.BindAddress
	if bindAddr == "" {
		bindAddr = exp.Listener.Address
	}
	port := exp.Port
	if port == 0 {
		port = exp.Listener.Port
	}
	socketDesc := fmt.Sprintf("%s:%d", bindAddr, port)
	nodes = append(nodes, PathNode{
		Step:        "Socket",
		Description: socketDesc,
		Detail:      fmt.Sprintf("Protocol: %s", exp.Protocol),
	})

	// 4. Network Interface(s)
	if len(exp.Interfaces) > 0 {
		if len(exp.Interfaces) == 1 {
			iface := exp.Interfaces[0]
			var desc string
			switch iface.Kind {
			case "LOOPBACK":
				desc = fmt.Sprintf("Loopback (%s)", iface.Name)
			case "VPN":
				desc = fmt.Sprintf("VPN interface (%s)", iface.Name)
			case "LAN":
				if iface.IP != "" {
					desc = fmt.Sprintf("%s (%s)", iface.Name, iface.IP)
				} else {
					desc = fmt.Sprintf("%s interface", iface.Name)
				}
			default:
				desc = fmt.Sprintf("%s interface", iface.Name)
			}
			nodes = append(nodes, PathNode{
				Step:        "Interface",
				Description: desc,
				Detail:      fmt.Sprintf("Interface: %s, IP: %s, Kind: %s", iface.Name, iface.IP, iface.Kind),
			})
		} else {
			var names []string
			for _, iface := range exp.Interfaces {
				names = append(names, iface.Name)
			}
			nodes = append(nodes, PathNode{
				Step:        "Interface",
				Description: fmt.Sprintf("Multiple interfaces (%s)", strings.Join(names, ", ")),
				Detail:      fmt.Sprintf("%d active interfaces matched", len(exp.Interfaces)),
			})
		}
	} else {
		cleanAddr := strings.Trim(strings.TrimSpace(bindAddr), "[]")
		if isLoopbackAddress(cleanAddr) {
			nodes = append(nodes, PathNode{
				Step:        "Interface",
				Description: "Loopback (lo)",
				Detail:      "Local loopback interface",
			})
		}
	}

	// 5. Reachability State
	reachDesc := formatReachability(exp.Reachability)
	nodes = append(nodes, PathNode{
		Step:        "Reachability",
		Description: reachDesc,
		Detail:      fmt.Sprintf("Local: %t, LAN: %s, Internet: %s, State: %s", exp.Reachability.Local, exp.Reachability.LAN, exp.Reachability.Internet, exp.Reachability.State),
	})

	return nodes
}

func formatReachability(reach domain.Reachability) string {
	switch reach.State {
	case "LOOPBACK_ONLY":
		return "Loopback only"
	case "LAN_REACHABLE":
		return "LAN reachable"
	case "VPN_REACHABLE":
		return "VPN reachable"
	case "MULTI_INTERFACE":
		return "Multiple interfaces reachable"
	case "UNRESOLVED":
		return "Reachability unresolved"
	default:
		if reach.LAN == "yes" || reach.LAN == "possible" {
			return "LAN reachable"
		}
		if reach.Local {
			return "Loopback only"
		}
		return "Reachability unknown"
	}
}

// FormatPath formats the exposure path as an ASCII tree using down arrows.
func FormatPath(exp *domain.Exposure, rc ...RootCause) string {
	nodes := BuildExposurePath(exp, rc...)
	if len(nodes) == 0 {
		return ""
	}

	var descriptions []string
	for _, n := range nodes {
		descriptions = append(descriptions, n.Description)
	}

	return strings.Join(descriptions, "\n       ↓\n")
}
