package network

import (
	"net"
	"testing"

	"lantern/internal/domain"
)

func TestClassifyIP_Loopback(t *testing.T) {
	tests := []struct {
		name       string
		ipStr      string
		ifaceName  string
		isLoopback bool
	}{
		{"127.0.0.1", "127.0.0.1", "lo", true},
		{"127.0.0.2", "127.0.0.2", "lo0", true},
		{"::1", "::1", "lo", true},
		{"loopback by flag only", "127.0.0.5", "eth0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			kind := ClassifyIP(ip, tt.ifaceName, tt.isLoopback)
			if kind != "LOOPBACK" {
				t.Errorf("expected LOOPBACK, got %s", kind)
			}
		})
	}
}

func TestClassifyIP_LAN(t *testing.T) {
	tests := []struct {
		name  string
		ipStr string
	}{
		{"10.0.0.1 (10/8)", "10.0.0.1"},
		{"10.254.1.5 (10/8)", "10.254.1.5"},
		{"172.16.0.1 (172.16/12)", "172.16.0.1"},
		{"172.31.255.254 (172.16/12)", "172.31.255.254"},
		{"192.168.1.1 (192.168/16)", "192.168.1.1"},
		{"192.168.100.50 (192.168/16)", "192.168.100.50"},
		{"fc00::1 (IPv6 ULA)", "fc00::1"},
		{"fd12:3456::1 (IPv6 ULA)", "fd12:3456::1"},
		{"fe80::1 (IPv6 Link-Local)", "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			kind := ClassifyIP(ip, "eth0", false)
			if kind != "LAN" {
				t.Errorf("expected LAN for %s, got %s", tt.ipStr, kind)
			}
		})
	}
}

func TestClassifyIP_Other(t *testing.T) {
	tests := []struct {
		name  string
		ipStr string
	}{
		{"8.8.8.8 (public DNS)", "8.8.8.8"},
		{"1.1.1.1 (Cloudflare)", "1.1.1.1"},
		{"172.32.0.1 (outside RFC1918)", "172.32.0.1"},
		{"2607:f8b0:4005:805::200e (Google public IPv6)", "2607:f8b0:4005:805::200e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			kind := ClassifyIP(ip, "eth0", false)
			if kind != "OTHER" {
				t.Errorf("expected OTHER for %s, got %s", tt.ipStr, kind)
			}
		})
	}
}

func TestClassifyIP_VPN(t *testing.T) {
	tests := []struct {
		name      string
		ifaceName string
		ipStr     string
	}{
		{"tun0", "tun0", "10.8.0.2"},
		{"tap1", "tap1", "192.168.5.10"},
		{"wg0 (wireguard)", "wg0", "10.0.0.2"},
		{"utun2 (macOS)", "utun2", "10.200.1.1"},
		{"tailscale0", "tailscale0", "100.64.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			kind := ClassifyIP(ip, tt.ifaceName, false)
			if kind != "VPN" {
				t.Errorf("expected VPN for %s on %s, got %s", tt.ipStr, tt.ifaceName, kind)
			}
		})
	}

	// Verify that private IP alone on non-VPN interface is NOT classified as VPN
	normalIP := net.ParseIP("10.8.0.2")
	kind := ClassifyIP(normalIP, "eth0", false)
	if kind == "VPN" {
		t.Errorf("private IP on eth0 must NOT be classified as VPN, got %s", kind)
	}
}

func TestEvaluateReachability_Loopback(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsLoopback: false, IsUp: true},
	}

	// 127.0.0.1
	reach4, relevant4 := EvaluateReachability("127.0.0.1", ifaces)
	if reach4.State != StateLoopbackOnly {
		t.Errorf("expected State %s, got %s", StateLoopbackOnly, reach4.State)
	}
	if !reach4.Local || reach4.LAN != "no" {
		t.Errorf("expected Local=true, LAN='no', got Local=%v, LAN=%s", reach4.Local, reach4.LAN)
	}
	if len(relevant4) != 1 || relevant4[0].Name != "lo" {
		t.Errorf("unexpected relevant interfaces: %+v", relevant4)
	}

	// ::1
	ifaces6 := append(ifaces, domain.NetworkInterface{
		Name: "lo", IP: "::1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true,
	})
	reach6, relevant6 := EvaluateReachability("::1", ifaces6)
	if reach6.State != StateLoopbackOnly {
		t.Errorf("expected State %s, got %s", StateLoopbackOnly, reach6.State)
	}
	if len(relevant6) == 0 {
		t.Errorf("expected relevant loopback interface for ::1")
	}
}

func TestEvaluateReachability_WildcardIPv4(t *testing.T) {
	// Case 1: 0.0.0.0 with single LAN interface
	ifacesSingleLAN := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.20", Kind: "LAN", IsLoopback: false, IsUp: true},
	}
	reach1, relevant1 := EvaluateReachability("0.0.0.0", ifacesSingleLAN)
	if reach1.State != StateLANReachable {
		t.Errorf("expected %s, got %s", StateLANReachable, reach1.State)
	}
	if !reach1.Local || reach1.LAN != "possible" {
		t.Errorf("expected Local=true, LAN='possible', got %+v", reach1)
	}
	if len(relevant1) != 2 { // lo and eth0 are both IPv4
		t.Errorf("expected 2 relevant interfaces, got %d", len(relevant1))
	}

	// Case 2: 0.0.0.0 with multiple active non-loopback interfaces (e.g. eth0 LAN + wg0 VPN)
	ifacesMulti := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.20", Kind: "LAN", IsLoopback: false, IsUp: true},
		{Name: "wg0", IP: "10.8.0.2", Kind: "VPN", IsLoopback: false, IsUp: true},
	}
	reach2, _ := EvaluateReachability("0.0.0.0", ifacesMulti)
	if reach2.State != StateMultiInterface {
		t.Errorf("expected %s for multiple interfaces, got %s", StateMultiInterface, reach2.State)
	}
	if reach2.LAN != "possible" {
		t.Errorf("expected LAN='possible', got %s", reach2.LAN)
	}
}

func TestEvaluateReachability_SpecificLAN(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.20", Kind: "LAN", IsLoopback: false, IsUp: true},
	}

	reach, relevant := EvaluateReachability("192.168.1.20", ifaces)
	if reach.State != StateLANReachable {
		t.Errorf("expected %s, got %s", StateLANReachable, reach.State)
	}
	if !reach.Local || reach.LAN != "possible" {
		t.Errorf("expected Local=true, LAN='possible', got %+v", reach)
	}
	if len(relevant) != 1 || relevant[0].IP != "192.168.1.20" {
		t.Errorf("expected relevant interface with IP 192.168.1.20, got %+v", relevant)
	}
}

func TestEvaluateReachability_SpecificVPN(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "tun0", IP: "10.8.0.5", Kind: "VPN", IsLoopback: false, IsUp: true},
	}

	reach, relevant := EvaluateReachability("10.8.0.5", ifaces)
	if reach.State != StateVPNReachable {
		t.Errorf("expected %s, got %s", StateVPNReachable, reach.State)
	}
	if !reach.Local || reach.LAN != "no" {
		t.Errorf("expected Local=true, LAN='no', got %+v", reach)
	}
	if len(relevant) != 1 || relevant[0].Name != "tun0" {
		t.Errorf("expected tun0 relevant interface, got %+v", relevant)
	}
}

func TestEvaluateReachability_UnmatchedAddress(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "eth0", IP: "192.168.1.20", Kind: "LAN", IsLoopback: false, IsUp: true},
	}

	// Address not assigned to any local interface
	reach, relevant := EvaluateReachability("192.168.200.5", ifaces)
	if reach.State != StateUnresolved {
		t.Errorf("expected %s, got %s", StateUnresolved, reach.State)
	}
	if reach.Local || reach.LAN != "no" {
		t.Errorf("expected Local=false, LAN='no', got %+v", reach)
	}
	if len(relevant) != 0 {
		t.Errorf("expected 0 relevant interfaces for unmatched address, got %d", len(relevant))
	}
}

func TestEvaluateReachability_DownInterfaceExcluded(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "eth0", IP: "192.168.1.20", Kind: "LAN", IsLoopback: false, IsUp: false}, // DOWN!
	}

	reach, relevant := EvaluateReachability("192.168.1.20", ifaces)
	if reach.State != StateUnresolved {
		t.Errorf("down interface should not be reachable, got state %s", reach.State)
	}
	if reach.Local {
		t.Errorf("down interface should not be Local=true")
	}
	if len(relevant) != 0 {
		t.Errorf("expected 0 relevant interfaces for down adapter, got %d", len(relevant))
	}
}

func TestEvaluateReachability_WildcardIPv6(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "::1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "fd00::1", Kind: "LAN", IsLoopback: false, IsUp: true},
	}

	reach, relevant := EvaluateReachability("::", ifaces)
	if reach.State != StateLANReachable {
		t.Errorf("expected %s for :: with IPv6 LAN interface, got %s", StateLANReachable, reach.State)
	}
	if len(relevant) != 2 {
		t.Errorf("expected 2 relevant IPv6 interfaces, got %d", len(relevant))
	}
}

func TestEvaluateReachability_MalformedAddress(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
	}

	reach, _ := EvaluateReachability("", ifaces)
	if reach.State != StateUnresolved {
		t.Errorf("expected %s for empty address, got %s", StateUnresolved, reach.State)
	}

	reach2, _ := EvaluateReachability("not-an-ip", ifaces)
	if reach2.State != StateUnresolved {
		t.Errorf("expected %s for garbage address, got %s", StateUnresolved, reach2.State)
	}
}
