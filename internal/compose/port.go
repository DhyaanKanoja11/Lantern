package compose

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"lantern/internal/domain"
)

// ParsedPort represents normalized port mapping attributes extracted from a Compose declaration.
type ParsedPort struct {
	HostIP        string // e.g. "127.0.0.1", "0.0.0.0", "::", "::1", or "" for default binding
	HostPortStart uint16
	HostPortEnd   uint16
	ContainerPort uint16
	Protocol      string // "tcp", "udp"
	Original      string
}

// IsEphemeral returns true if no host port was declared (container port only).
func (p *ParsedPort) IsEphemeral() bool {
	return p.HostPortStart == 0 && p.HostPortEnd == 0
}

// MatchesPort returns true if hostPort is within the declared published port range.
// For ephemeral port declarations (container port only), it returns false because
// the host port cannot be matched without container runtime port mappings.
func (p *ParsedPort) MatchesPort(hostPort uint16) bool {
	if p.IsEphemeral() {
		return false
	}
	return hostPort >= p.HostPortStart && hostPort <= p.HostPortEnd
}

// MatchesContainerPort returns true if an ephemeral port declaration matches
// the hostPort through the container's observed runtime port mappings.
func (p *ParsedPort) MatchesContainerPort(hostPort uint16, container *domain.Container) bool {
	if !p.IsEphemeral() || container == nil {
		return false
	}
	for _, m := range container.Ports {
		if m.HostPort == hostPort && m.ContainerPort == p.ContainerPort {
			return true
		}
	}
	return false
}

// MatchesAddress returns true if hostAddress matches the declared host IP.
// Unconstrained Compose bindings (HostIP == "") match any host address (Docker default binding).
// Explicit bindings (e.g. 127.0.0.1 vs 0.0.0.0) require exact address match.
func (p *ParsedPort) MatchesAddress(hostAddress string) bool {
	hostAddress = strings.Trim(strings.TrimSpace(hostAddress), "[]")
	if hostAddress == "" {
		return true
	}
	if p.HostIP == "" {
		return true
	}
	cleanHostIP := strings.Trim(strings.TrimSpace(p.HostIP), "[]")
	return cleanHostIP == hostAddress
}

// MatchesProtocol returns true if proto matches the declared protocol (case-insensitive).
func (p *ParsedPort) MatchesProtocol(proto string) bool {
	if proto == "" || p.Protocol == "" {
		return true
	}
	return strings.EqualFold(p.Protocol, proto)
}

// parsePortShort parses a Compose short syntax port string into a ParsedPort.
// Supported syntaxes:
//
//	"5432:5432"
//	"127.0.0.1:5432:5432"
//	"0.0.0.0:5432:5432"
//	"[::1]:5432:5432"
//	"[::]:5432:5432"
//	"5432:5432/tcp"
//	"5432:5432/udp"
//	"127.0.0.1:5432:5432/tcp"
//	"8080-8085:80-85"
//	"5432" (container port only)
func parsePortShort(raw string) (*ParsedPort, error) {
	orig := raw
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty port declaration")
	}

	proto := "tcp"
	if idx := strings.LastIndex(raw, "/"); idx != -1 {
		proto = strings.ToLower(strings.TrimSpace(raw[idx+1:]))
		raw = raw[:idx]
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("unsupported protocol %q in port declaration %q", proto, orig)
		}
	}

	var hostIP string
	if strings.HasPrefix(raw, "[") {
		closeIdx := strings.Index(raw, "]")
		if closeIdx == -1 {
			return nil, fmt.Errorf("unmatched ipv6 bracket in %q", orig)
		}
		hostIP = raw[1:closeIdx]
		raw = raw[closeIdx+1:]
		if strings.HasPrefix(raw, ":") {
			raw = raw[1:]
		} else if raw != "" {
			return nil, fmt.Errorf("unexpected character after ipv6 bracket in %q", orig)
		}
	}

	var hostPortPart, containerPortPart string

	if hostIP != "" {
		// Had IPv6 prefix, remainder is hostPort:containerPort or containerPort
		parts := strings.Split(raw, ":")
		switch len(parts) {
		case 2:
			hostPortPart = parts[0]
			containerPortPart = parts[1]
		case 1:
			containerPortPart = parts[0]
		default:
			return nil, fmt.Errorf("invalid ipv6 port format in %q", orig)
		}
	} else {
		colonCount := strings.Count(raw, ":")
		switch colonCount {
		case 2:
			// hostIP:hostPort:containerPort
			parts := strings.Split(raw, ":")
			hostIP = parts[0]
			hostPortPart = parts[1]
			containerPortPart = parts[2]
		case 1:
			parts := strings.Split(raw, ":")
			if net.ParseIP(parts[0]) != nil {
				// hostIP:containerPort (ephemeral host port)
				hostIP = parts[0]
				containerPortPart = parts[1]
			} else {
				// hostPort:containerPort
				hostPortPart = parts[0]
				containerPortPart = parts[1]
			}
		case 0:
			// containerPort only
			containerPortPart = raw
		default:
			return nil, fmt.Errorf("too many colons in port declaration %q", orig)
		}
	}

	parsed := &ParsedPort{
		HostIP:   strings.Trim(strings.TrimSpace(hostIP), "[]"),
		Protocol: proto,
		Original: orig,
	}

	if hostPortPart != "" {
		start, end, err := parsePortRange(hostPortPart)
		if err != nil {
			return nil, fmt.Errorf("invalid host port %q in %q: %w", hostPortPart, orig, err)
		}
		parsed.HostPortStart = start
		parsed.HostPortEnd = end
	}

	if containerPortPart != "" {
		start, _, err := parsePortRange(containerPortPart)
		if err != nil {
			return nil, fmt.Errorf("invalid container port %q in %q: %w", containerPortPart, orig, err)
		}
		parsed.ContainerPort = start
	} else {
		return nil, fmt.Errorf("missing container port in %q", orig)
	}

	return parsed, nil
}

// parsePortRange parses a port number or range string (e.g. "5432" or "8080-8085").
func parsePortRange(s string) (uint16, uint16, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid range %q", s)
		}
		start, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		end, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err1 != nil || err2 != nil || start == 0 || end == 0 || start > end {
			return 0, 0, fmt.Errorf("invalid range values %q", s)
		}
		return uint16(start), uint16(end), nil
	}

	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil || val == 0 {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(val), uint16(val), nil
}

// parsePortLong parses a Compose long syntax port mapping node.
// Syntax:
//
//	target: 5432
//	published: 5432
//	protocol: tcp
//	host_ip: 127.0.0.1
func parsePortLong(node *yaml.Node) (*ParsedPort, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node for long syntax port, got kind %d", node.Kind)
	}

	var targetStr, publishedStr, protocolStr, hostIPStr string

	for i := 0; i < len(node.Content)-1; i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		switch keyNode.Value {
		case "target":
			targetStr = valNode.Value
		case "published":
			publishedStr = valNode.Value
		case "protocol":
			protocolStr = strings.ToLower(strings.TrimSpace(valNode.Value))
		case "host_ip":
			hostIPStr = strings.Trim(strings.TrimSpace(valNode.Value), "[]")
		}
	}

	if targetStr == "" {
		return nil, fmt.Errorf("missing target in long syntax port mapping")
	}

	proto := "tcp"
	if protocolStr != "" {
		proto = protocolStr
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("unsupported protocol %q in long syntax port mapping", proto)
		}
	}

	parsed := &ParsedPort{
		HostIP:   hostIPStr,
		Protocol: proto,
	}

	cStart, _, err := parsePortRange(targetStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q: %w", targetStr, err)
	}
	parsed.ContainerPort = cStart

	if publishedStr != "" {
		hStart, hEnd, err := parsePortRange(publishedStr)
		if err != nil {
			return nil, fmt.Errorf("invalid published port %q: %w", publishedStr, err)
		}
		parsed.HostPortStart = hStart
		parsed.HostPortEnd = hEnd
	}

	var origParts []string
	if publishedStr != "" {
		origParts = append(origParts, fmt.Sprintf("published: %s", publishedStr))
	}
	origParts = append(origParts, fmt.Sprintf("target: %s", targetStr))
	if proto != "" {
		origParts = append(origParts, fmt.Sprintf("protocol: %s", proto))
	}
	if hostIPStr != "" {
		origParts = append(origParts, fmt.Sprintf("host_ip: %s", hostIPStr))
	}
	parsed.Original = strings.Join(origParts, ", ")

	return parsed, nil
}
