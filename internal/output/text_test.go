package output

import (
	"bytes"
	"strings"
	"testing"

	"lantern/internal/domain"
)

func TestTextFormatter_RenderScan_Empty(t *testing.T) {
	formatter := NewTextFormatter()
	buf := new(bytes.Buffer)

	err := formatter.RenderScan(buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No active TCP listening sockets detected.") {
		t.Errorf("expected no active sockets message, got: %s", out)
	}
}

func TestTextFormatter_RenderScan_Populated(t *testing.T) {
	formatter := NewTextFormatter()
	buf := new(bytes.Buffer)

	list := []domain.ExposureSummary{
		{
			Port:          5432,
			Protocol:      "tcp",
			Address:       "0.0.0.0",
			ProcessName:   "docker-proxy",
			ContainerName: "postgres",
			Reachability:  "LAN reachable",
		},
		{
			Port:          8080,
			Protocol:      "tcp",
			Address:       "127.0.0.1",
			ProcessName:   "node",
			ContainerName: "-",
			Reachability:  "localhost only",
		},
	}

	err := formatter.RenderScan(buf, list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	expectedHeaders := []string{"PORT", "ADDRESS", "PROCESS", "CONTAINER", "REACHABILITY"}
	for _, h := range expectedHeaders {
		if !strings.Contains(out, h) {
			t.Errorf("expected header %s in scan output:\n%s", h, out)
		}
	}

	if !strings.Contains(out, "5432") || !strings.Contains(out, "postgres") || !strings.Contains(out, "LAN reachable") {
		t.Errorf("expected postgres 5432 in scan output:\n%s", out)
	}
	if !strings.Contains(out, "8080") || !strings.Contains(out, "node") || !strings.Contains(out, "localhost only") {
		t.Errorf("expected node 8080 in scan output:\n%s", out)
	}
}

func TestTextFormatter_RenderWhy_ComposeExposure(t *testing.T) {
	formatter := NewTextFormatter()
	buf := new(bytes.Buffer)

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
			Image: "postgres:15",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          "/app/docker-compose.yml",
			Line:          18,
			Evidence:      "5432:5432",
			Original:      "5432:5432",
			Service:       "db",
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
		Recommendation: &domain.Recommendation{
			Type:        "bind_localhost",
			Current:     "5432:5432",
			Suggested:   "127.0.0.1:5432:5432",
			Description: "Bind published port to localhost (127.0.0.1)",
		},
	}

	err := formatter.RenderWhy(buf, exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Verify sections
	sections := []string{
		"postgres :5432",
		"EXPOSURE PATH",
		"docker-compose.yml",
		"5432:5432",
		"Docker container: postgres",
		"0.0.0.0:5432",
		"eth0 (192.168.1.50)",
		"LAN reachable",
		"ROOT CAUSE",
		"/app/docker-compose.yml:18",
		"REACHABILITY",
		"Local machine: YES",
		"LAN:           YES",
		"Internet:      UNKNOWN",
		"RECOMMENDED CHANGE",
		"127.0.0.1:5432:5432",
	}

	for _, s := range sections {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q, but got:\n%s", s, out)
		}
	}
}

func TestTextFormatter_RenderWhy_RejectedComposeEvidence(t *testing.T) {
	formatter := NewTextFormatter()
	buf := new(bytes.Buffer)

	// Docker mapped on 127.0.0.1, Compose declared 0.0.0.0 (rejected)
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
		Config: &domain.ConfigEvidence{
			File:          "/app/docker-compose.yml",
			Line:          18,
			Evidence:      "0.0.0.0:5432:5432",
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       true,
		},
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    "LOOPBACK_ONLY",
		},
	}

	err := formatter.RenderWhy(buf, exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Should be labeled LIKELY SOURCE (uncertain) because Compose was rejected
	if !strings.Contains(out, "LIKELY SOURCE") {
		t.Errorf("expected LIKELY SOURCE title for uncertain Docker mapping, got:\n%s", out)
	}

	// The rejected compose file must NOT appear in the EXPOSURE PATH
	pathIdx := strings.Index(out, "EXPOSURE PATH")
	rcIdx := strings.Index(out, "LIKELY SOURCE")
	if pathIdx >= 0 && rcIdx > pathIdx {
		pathSection := out[pathIdx:rcIdx]
		if strings.Contains(pathSection, "docker-compose.yml") {
			t.Errorf("rejected compose file must NOT appear in EXPOSURE PATH section:\n%s", pathSection)
		}
	}

	// Zero false Internet claims
	if !strings.Contains(out, "Internet:      UNKNOWN") {
		t.Errorf("expected Internet: UNKNOWN, got:\n%s", out)
	}
}

func TestTextFormatter_RenderWhy_NativeLoopback(t *testing.T) {
	formatter := NewTextFormatter()
	buf := new(bytes.Buffer)

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
		Reachability: domain.Reachability{
			Local:    true,
			LAN:      "no",
			Internet: "unknown",
			State:    "LOOPBACK_ONLY",
		},
	}

	err := formatter.RenderWhy(buf, exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "node :3000") {
		t.Errorf("expected node :3000 header, got:\n%s", out)
	}
	if !strings.Contains(out, "ROOT CAUSE") {
		t.Errorf("expected ROOT CAUSE for native loopback, got:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:3000") {
		t.Errorf("expected 127.0.0.1:3000, got:\n%s", out)
	}
	if !strings.Contains(out, "Local machine: YES") || !strings.Contains(out, "LAN:           NO") {
		t.Errorf("expected Local YES and LAN NO, got:\n%s", out)
	}
	// No recommended change for already-loopback service
	if strings.Contains(out, "RECOMMENDED CHANGE") {
		t.Errorf("loopback service should not have RECOMMENDED CHANGE section, got:\n%s", out)
	}
}
