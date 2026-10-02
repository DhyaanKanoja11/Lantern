package explain

import (
	"strings"
	"testing"

	"lantern/internal/domain"
)

func TestExplain_ComposeExposure(t *testing.T) {
	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "0.0.0.0",
			Port:     5432,
		},
		Container: &domain.Container{
			ID:    "c_pg",
			Name:  "postgres",
			Image: "postgres:15-alpine",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          "/home/dev/app/docker-compose.yml",
			Line:          18,
			Evidence:      "5432:5432",
			Original:      "5432:5432",
			Service:       "postgres",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       true,
		},
		Interfaces: []domain.NetworkInterface{
			{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsUp: true},
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "yes",
			Internet: "unknown",
			State:    "LAN_REACHABLE",
		},
	}

	explainer := NewDefaultExplainer()
	explanation := explainer.Explain(exp)

	if explanation == nil {
		t.Fatal("expected non-nil explanation")
	}
	if explanation.Port != 5432 {
		t.Errorf("expected port 5432, got %d", explanation.Port)
	}
	if explanation.RootCause.Type != RootCauseComposePublishedPort {
		t.Errorf("expected root cause %s, got %s", RootCauseComposePublishedPort, explanation.RootCause.Type)
	}
	if !explanation.RootCause.Certain {
		t.Errorf("expected root cause Certain == true")
	}

	// Verify Summary
	if !strings.Contains(explanation.Summary, "Docker Compose") {
		t.Errorf("expected summary to mention Docker Compose: %s", explanation.Summary)
	}
	if strings.Contains(strings.ToLower(explanation.Summary), "internet exposed") {
		t.Errorf("summary must not claim Internet exposure: %s", explanation.Summary)
	}

	// Verify Path formatting
	pathTree := explainer.FormatPath(exp)
	expectedTreeFragments := []string{
		"docker-compose.yml",
		"5432:5432",
		"Docker container: postgres",
		"0.0.0.0:5432",
		"eth0 (192.168.1.50)",
		"LAN reachable",
	}
	for _, frag := range expectedTreeFragments {
		if !strings.Contains(pathTree, frag) {
			t.Errorf("expected path tree to contain %q, but got:\n%s", frag, pathTree)
		}
	}
	if !strings.Contains(pathTree, "       ↓\n") {
		t.Errorf("expected down arrows in path tree:\n%s", pathTree)
	}
}

func TestExplain_DockerWithoutCompose(t *testing.T) {
	exp := &domain.Exposure{
		Port:        6379,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "0.0.0.0",
			Port:     6379,
		},
		Container: &domain.Container{
			ID:    "c_redis",
			Name:  "my-redis",
			Image: "redis:latest",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      6379,
			ContainerPort: 6379,
			Protocol:      "tcp",
		},
		Interfaces: []domain.NetworkInterface{
			{Name: "wlan0", IP: "192.168.1.100", Kind: "LAN", IsUp: true},
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "yes",
			Internet: "unknown",
			State:    "LAN_REACHABLE",
		},
	}

	expl := Explain(exp)
	if expl.RootCause.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected root cause %s, got %s", RootCauseDockerPublishedPort, expl.RootCause.Type)
	}
	if !expl.RootCause.Certain {
		t.Errorf("expected Certain == true")
	}

	formatted := FormatPath(exp)
	if !strings.Contains(formatted, "Docker container: my-redis") {
		t.Errorf("expected container in path, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "0.0.0.0:6379 -> 6379/tcp") {
		t.Errorf("expected port mapping in path, got:\n%s", formatted)
	}
}

func TestExplain_NativeLoopback(t *testing.T) {
	exp := &domain.Exposure{
		Port:        3000,
		Protocol:    "tcp",
		BindAddress: "127.0.0.1",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "127.0.0.1",
			Port:     3000,
		},
		Process: &domain.Process{
			PID:  1234,
			Name: "node",
		},
		Interfaces: []domain.NetworkInterface{
			{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    "LOOPBACK_ONLY",
		},
	}

	expl := Explain(exp)
	if expl.RootCause.Type != RootCauseProcessLoopbackBind {
		t.Errorf("expected %s, got %s", RootCauseProcessLoopbackBind, expl.RootCause.Type)
	}
	if !strings.Contains(expl.Summary, "Not reachable from external networks") {
		t.Errorf("expected summary to state not reachable externally: %s", expl.Summary)
	}

	tree := FormatPath(exp)
	if !strings.Contains(tree, "Loopback only") {
		t.Errorf("expected 'Loopback only' in tree:\n%s", tree)
	}
}

func TestExplain_VPNReachability(t *testing.T) {
	exp := &domain.Exposure{
		Port:        8443,
		Protocol:    "tcp",
		BindAddress: "10.8.0.5",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "10.8.0.5",
			Port:     8443,
		},
		Process: &domain.Process{
			PID:  5555,
			Name: "vpn-service",
		},
		Interfaces: []domain.NetworkInterface{
			{Name: "tun0", IP: "10.8.0.5", Kind: "VPN", IsUp: true},
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    "VPN_REACHABLE",
		},
	}

	expl := Explain(exp)
	if expl.Reachability.State != "VPN_REACHABLE" {
		t.Errorf("expected reachability state VPN_REACHABLE, got %s", expl.Reachability.State)
	}
	if !strings.Contains(expl.Summary, "VPN reachable") {
		t.Errorf("expected summary to reflect VPN reachable: %s", expl.Summary)
	}
	if strings.Contains(strings.ToLower(expl.Summary), "internet") {
		t.Errorf("VPN service must not be claimed as Internet reachable: %s", expl.Summary)
	}
}

func TestExplain_MultiInterface(t *testing.T) {
	exp := &domain.Exposure{
		Port:        9090,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "0.0.0.0",
			Port:     9090,
		},
		Process: &domain.Process{
			PID:  4444,
			Name: "prometheus",
		},
		Interfaces: []domain.NetworkInterface{
			{Name: "eth0", IP: "192.168.1.10", Kind: "LAN", IsUp: true},
			{Name: "tun0", IP: "10.8.0.2", Kind: "VPN", IsUp: true},
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "yes",
			Internet: "unknown",
			State:    "MULTI_INTERFACE",
		},
	}

	expl := Explain(exp)
	if expl.Reachability.State != "MULTI_INTERFACE" {
		t.Errorf("expected MULTI_INTERFACE state, got %s", expl.Reachability.State)
	}
	if !strings.Contains(expl.Summary, "Multiple interfaces reachable") {
		t.Errorf("expected summary to preserve multi-interface reachability: %s", expl.Summary)
	}

	tree := FormatPath(exp)
	if !strings.Contains(tree, "Multiple interfaces (eth0, tun0)") {
		t.Errorf("expected multiple interfaces in tree:\n%s", tree)
	}
}

func TestExplain_NilAndZero(t *testing.T) {
	if Explain(nil) != nil {
		t.Error("expected nil for Explain(nil)")
	}
	if BuildExposurePath(nil) != nil {
		t.Error("expected nil for BuildExposurePath(nil)")
	}
	if FormatPath(nil) != "" {
		t.Error("expected empty string for FormatPath(nil)")
	}
}

// Regression Test 4: Rejected Compose evidence must disappear from exposure path (Finding 2)
func TestBuildExposurePath_RejectedComposeDisappears(t *testing.T) {
	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "127.0.0.1",
		Listener: domain.Listener{
			Protocol: "tcp",
			Address:  "127.0.0.1",
			Port:     5432,
		},
		Container: &domain.Container{
			ID:    "c_pg",
			Name:  "postgres",
			Image: "postgres:15",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "127.0.0.1",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		// Rejected Compose config (mismatched port 9999)
		Config: &domain.ConfigEvidence{
			File:          "/app/docker-compose.yml",
			Line:          18,
			Evidence:      "9999:9999",
			HostPort:      9999,
			ContainerPort: 9999,
			Certain:       true,
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    "LOOPBACK_ONLY",
		},
	}

	expl := Explain(exp)
	if expl.RootCause.Type == RootCauseComposePublishedPort {
		t.Fatalf("mismatched Compose config must NOT be classified as RootCauseComposePublishedPort")
	}

	// Verify that BuildExposurePath does NOT contain Compose file or declaration
	nodes := BuildExposurePath(exp, expl.RootCause)
	for _, n := range nodes {
		if n.Step == "Configuration" || strings.Contains(n.Description, "docker-compose.yml") {
			t.Errorf("rejected Compose file node must NOT appear in exposure path: %+v", n)
		}
		if n.Step == "Port Declaration" || strings.Contains(n.Description, "9999:9999") {
			t.Errorf("rejected Compose port declaration must NOT appear in exposure path: %+v", n)
		}
	}

	// Verify ASCII tree representation
	pathTree := FormatPath(exp, expl.RootCause)
	if strings.Contains(pathTree, "docker-compose.yml") {
		t.Errorf("path tree must NOT contain rejected compose file:\n%s", pathTree)
	}
	if strings.Contains(pathTree, "9999:9999") {
		t.Errorf("path tree must NOT contain rejected port declaration:\n%s", pathTree)
	}
	if !strings.Contains(pathTree, "Docker container: postgres") {
		t.Errorf("expected Docker container node in path tree:\n%s", pathTree)
	}
}
