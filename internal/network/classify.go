package network

import (
	"net"
	"strings"

	"lantern/internal/domain"
)

var (
	_, rfc1918_10, _  = net.ParseCIDR("10.0.0.0/8")
	_, rfc1918_172, _ = net.ParseCIDR("172.16.0.0/12")
	_, rfc1918_192, _ = net.ParseCIDR("192.168.0.0/16")
	_, rfc4193_ula, _ = net.ParseCIDR("fc00::/7")
	_, rfc4291_ll, _  = net.ParseCIDR("fe80::/10")
)

// Reachability state constants.
const (
	StateLoopbackOnly   = "LOOPBACK_ONLY"
	StateLANReachable   = "LAN_REACHABLE"
	StateVPNReachable   = "VPN_REACHABLE"
	StateMultiInterface = "MULTI_INTERFACE"
	StateUnresolved     = "UNRESOLVED"
	StateOtherReachable = "OTHER_REACHABLE"
)

// ClassifyIP determines whether an IP and interface combination represents LOOPBACK, LAN, VPN, or OTHER.
func ClassifyIP(ip net.IP, ifaceName string, isLoopback bool) string {
	if ip == nil {
		return "OTHER"
	}

	// 1. Loopback
	if isLoopback || ip.IsLoopback() || ifaceName == "lo" || strings.HasPrefix(strings.ToLower(ifaceName), "lo") {
		return "LOOPBACK"
	}

	// 2. VPN - Conservative heuristic based on deterministic virtual driver prefixes
	nameLower := strings.ToLower(ifaceName)
	vpnPrefixes := []string{"tun", "tap", "wg", "utun", "ppp", "tailscale", "cscotun"}
	for _, prefix := range vpnPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return "VPN"
		}
	}

	// 3. LAN - RFC 1918 IPv4 private ranges & IPv6 ULA/Link-Local
	if rfc1918_10.Contains(ip) || rfc1918_172.Contains(ip) || rfc1918_192.Contains(ip) {
		return "LAN"
	}
	if rfc4193_ula.Contains(ip) || rfc4291_ll.Contains(ip) {
		return "LAN"
	}

	return "OTHER"
}

// EvaluateReachability computes Reachability and identifies relevant interfaces for a listener bind address.
func EvaluateReachability(bindAddr string, ifaces []domain.NetworkInterface) (domain.Reachability, []domain.NetworkInterface) {
	bindAddr = strings.TrimSpace(bindAddr)
	bindAddr = strings.Trim(bindAddr, "[]")

	unresolved := domain.Reachability{
		Local:    false,
		LAN:      "no",
		Internet: "unknown",
		State:    StateUnresolved,
	}

	if bindAddr == "" {
		return unresolved, nil
	}

	// Filter to active/up interfaces only for reachable paths
	var active []domain.NetworkInterface
	for _, iface := range ifaces {
		if iface.IsUp {
			active = append(active, iface)
		}
	}

	if len(active) == 0 {
		return unresolved, nil
	}

	// Case A: Loopback (127.0.0.1 or ::1)
	if bindAddr == "127.0.0.1" || bindAddr == "::1" || strings.HasPrefix(bindAddr, "127.") {
		var loopbackIfaces []domain.NetworkInterface
		for _, iface := range active {
			if iface.IsLoopback || iface.Kind == "LOOPBACK" {
				loopbackIfaces = append(loopbackIfaces, iface)
			}
		}
		return domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    StateLoopbackOnly,
		}, loopbackIfaces
	}

	// Case B: IPv4 Wildcard (0.0.0.0)
	if bindAddr == "0.0.0.0" || bindAddr == "*" {
		var relevant []domain.NetworkInterface
		var nonLoopback []domain.NetworkInterface

		for _, iface := range active {
			// Check if interface has an IPv4 address
			ip := net.ParseIP(iface.IP)
			if ip != nil && ip.To4() != nil {
				relevant = append(relevant, iface)
				if !iface.IsLoopback && iface.Kind != "LOOPBACK" {
					nonLoopback = append(nonLoopback, iface)
				}
			}
		}

		if len(nonLoopback) == 0 {
			return domain.Reachability{
				Local:    true,
				LAN:      "no",
				Internet: "unknown",
				State:    StateLoopbackOnly,
			}, relevant
		}

		if len(nonLoopback) > 1 {
			return domain.Reachability{
				Local:    true,
				LAN:      "possible",
				Internet: "unknown",
				State:    StateMultiInterface,
			}, relevant
		}

		// Exactly 1 non-loopback interface
		single := nonLoopback[0]
		if single.Kind == "LAN" {
			return domain.Reachability{
				Local:    true,
				LAN:      "possible",
				Internet: "unknown",
				State:    StateLANReachable,
			}, relevant
		}
		if single.Kind == "VPN" {
			return domain.Reachability{
				Local:    true,
				LAN:      "no",
				Internet: "unknown",
				State:    StateVPNReachable,
			}, relevant
		}
		return domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    StateOtherReachable,
		}, relevant
	}

	// Case C: IPv6 Wildcard (::)
	if bindAddr == "::" {
		var relevant []domain.NetworkInterface
		var nonLoopback []domain.NetworkInterface

		for _, iface := range active {
			ip := net.ParseIP(iface.IP)
			if ip != nil && ip.To4() == nil {
				relevant = append(relevant, iface)
				if !iface.IsLoopback && iface.Kind != "LOOPBACK" {
					nonLoopback = append(nonLoopback, iface)
				}
			}
		}

		if len(nonLoopback) == 0 {
			return domain.Reachability{
				Local:    true,
				LAN:      "no",
				Internet: "unknown",
				State:    StateLoopbackOnly,
			}, relevant
		}

		if len(nonLoopback) > 1 {
			return domain.Reachability{
				Local:    true,
				LAN:      "possible",
				Internet: "unknown",
				State:    StateMultiInterface,
			}, relevant
		}

		single := nonLoopback[0]
		if single.Kind == "LAN" {
			return domain.Reachability{
				Local:    true,
				LAN:      "possible",
				Internet: "unknown",
				State:    StateLANReachable,
			}, relevant
		}
		if single.Kind == "VPN" {
			return domain.Reachability{
				Local:    true,
				LAN:      "no",
				Internet: "unknown",
				State:    StateVPNReachable,
			}, relevant
		}
		return domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    StateOtherReachable,
		}, relevant
	}

	// Case D: Specific IP address
	var matched *domain.NetworkInterface
	for i := range active {
		if active[i].IP == bindAddr {
			matched = &active[i]
			break
		}
	}

	if matched == nil {
		return unresolved, nil
	}

	relevant := []domain.NetworkInterface{*matched}
	if matched.Kind == "LOOPBACK" {
		return domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    StateLoopbackOnly,
		}, relevant
	}
	if matched.Kind == "LAN" {
		return domain.Reachability{
			Local:    true,
			LAN:      "possible",
			Internet: "unknown",
			State:    StateLANReachable,
		}, relevant
	}
	if matched.Kind == "VPN" {
		return domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    StateVPNReachable,
		}, relevant
	}

	return domain.Reachability{
		Local:    true,
		LAN:      "no",
		Internet: "unknown",
		State:    StateOtherReachable,
	}, relevant
}
