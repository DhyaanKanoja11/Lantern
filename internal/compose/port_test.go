package compose

import (
	"testing"

	"gopkg.in/yaml.v3"

	"lantern/internal/domain"
)

func TestParsePortShort(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantHostIP    string
		wantHostStart uint16
		wantHostEnd   uint16
		wantContainer uint16
		wantProto     string
		wantErr       bool
	}{
		{
			name:          "simple short syntax",
			raw:           "5432:5432",
			wantHostIP:    "",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "explicit localhost",
			raw:           "127.0.0.1:5432:5432",
			wantHostIP:    "127.0.0.1",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "explicit wildcard IPv4",
			raw:           "0.0.0.0:5432:5432",
			wantHostIP:    "0.0.0.0",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "IPv6 wildcard",
			raw:           "[::]:5432:5432",
			wantHostIP:    "::",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "IPv6 localhost",
			raw:           "[::1]:5432:5432",
			wantHostIP:    "::1",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "protocol tcp",
			raw:           "5432:5432/tcp",
			wantHostIP:    "",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "protocol udp",
			raw:           "5432:5432/udp",
			wantHostIP:    "",
			wantHostStart: 5432,
			wantHostEnd:   5432,
			wantContainer: 5432,
			wantProto:     "udp",
			wantErr:       false,
		},
		{
			name:          "port range",
			raw:           "8080-8085:80-85",
			wantHostIP:    "",
			wantHostStart: 8080,
			wantHostEnd:   8085,
			wantContainer: 80,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:          "container port only",
			raw:           "5432",
			wantHostIP:    "",
			wantHostStart: 0,
			wantHostEnd:   0,
			wantContainer: 5432,
			wantProto:     "tcp",
			wantErr:       false,
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "malformed non-numeric",
			raw:     "abc:def",
			wantErr: true,
		},
		{
			name:    "malformed port overflow",
			raw:     "70000:5432",
			wantErr: true,
		},
		{
			name:    "malformed unmatched ipv6 bracket",
			raw:     "[::1:5432:5432",
			wantErr: true,
		},
		{
			name:    "unsupported protocol",
			raw:     "5432:5432/sctp",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePortShort(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePortShort(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.HostIP != tt.wantHostIP {
				t.Errorf("HostIP = %q, want %q", got.HostIP, tt.wantHostIP)
			}
			if got.HostPortStart != tt.wantHostStart {
				t.Errorf("HostPortStart = %d, want %d", got.HostPortStart, tt.wantHostStart)
			}
			if got.HostPortEnd != tt.wantHostEnd {
				t.Errorf("HostPortEnd = %d, want %d", got.HostPortEnd, tt.wantHostEnd)
			}
			if got.ContainerPort != tt.wantContainer {
				t.Errorf("ContainerPort = %d, want %d", got.ContainerPort, tt.wantContainer)
			}
			if got.Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", got.Protocol, tt.wantProto)
			}
		})
	}
}

func TestParsePortLong(t *testing.T) {
	yamlInput := `
target: 5432
published: 5432
protocol: tcp
host_ip: 127.0.0.1
`
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(yamlInput), &node); err != nil {
		t.Fatalf("failed to unmarshal yaml: %v", err)
	}

	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		t.Fatalf("unexpected yaml node: %+v", node)
	}

	parsed, err := parsePortLong(node.Content[0])
	if err != nil {
		t.Fatalf("parsePortLong error: %v", err)
	}

	if parsed.HostIP != "127.0.0.1" {
		t.Errorf("HostIP = %q, want 127.0.0.1", parsed.HostIP)
	}
	if parsed.HostPortStart != 5432 || parsed.HostPortEnd != 5432 {
		t.Errorf("HostPort = %d-%d, want 5432", parsed.HostPortStart, parsed.HostPortEnd)
	}
	if parsed.ContainerPort != 5432 {
		t.Errorf("ContainerPort = %d, want 5432", parsed.ContainerPort)
	}
	if parsed.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", parsed.Protocol)
	}
}

func TestMatchesAddress_Distinction(t *testing.T) {
	// Case 1: unconstrained binding in Compose matches anything
	unconstrained := &ParsedPort{HostIP: ""}
	if !unconstrained.MatchesAddress("0.0.0.0") {
		t.Errorf("unconstrained port should match 0.0.0.0")
	}
	if !unconstrained.MatchesAddress("127.0.0.1") {
		t.Errorf("unconstrained port should match 127.0.0.1")
	}
	if !unconstrained.MatchesAddress("") {
		t.Errorf("unconstrained port should match empty address")
	}

	// Case 2: explicit localhost in Compose
	localhost := &ParsedPort{HostIP: "127.0.0.1"}
	if !localhost.MatchesAddress("127.0.0.1") {
		t.Errorf("127.0.0.1 should match 127.0.0.1")
	}
	if localhost.MatchesAddress("0.0.0.0") {
		t.Errorf("127.0.0.1 should NOT match 0.0.0.0")
	}

	// Case 3: explicit wildcard in Compose
	wildcard := &ParsedPort{HostIP: "0.0.0.0"}
	if !wildcard.MatchesAddress("0.0.0.0") {
		t.Errorf("0.0.0.0 should match 0.0.0.0")
	}
	if wildcard.MatchesAddress("127.0.0.1") {
		t.Errorf("0.0.0.0 should NOT match 127.0.0.1")
	}

	// Case 4: IPv6 wildcard in Compose
	wildcard6 := &ParsedPort{HostIP: "::"}
	if !wildcard6.MatchesAddress("::") {
		t.Errorf(":: should match ::")
	}
	if !wildcard6.MatchesAddress("[::]") {
		t.Errorf(":: should match [::]")
	}
	if wildcard6.MatchesAddress("127.0.0.1") {
		t.Errorf(":: should NOT match 127.0.0.1")
	}
}

func TestMatchesPort_Ephemeral(t *testing.T) {
	// Ephemeral container-only port (e.g. "5432") must NOT match any hostPort directly via MatchesPort
	ephemeral := &ParsedPort{
		HostIP:        "",
		HostPortStart: 0,
		HostPortEnd:   0,
		ContainerPort: 5432,
		Protocol:      "tcp",
	}

	if !ephemeral.IsEphemeral() {
		t.Errorf("expected IsEphemeral to be true")
	}
	if ephemeral.MatchesPort(5432) {
		t.Errorf("ephemeral port '5432' must NOT match hostPort 5432 directly")
	}
	if ephemeral.MatchesPort(49153) {
		t.Errorf("ephemeral port '5432' must NOT match hostPort 49153 directly")
	}

	// Normal explicit port must match its hostPort
	explicit := &ParsedPort{
		HostPortStart: 5432,
		HostPortEnd:   5432,
		ContainerPort: 5432,
	}
	if explicit.IsEphemeral() {
		t.Errorf("explicit port must not be ephemeral")
	}
	if !explicit.MatchesPort(5432) {
		t.Errorf("explicit port 5432 should match 5432")
	}
}

func TestMatchesContainerPort(t *testing.T) {
	ephemeral := &ParsedPort{
		HostIP:        "",
		HostPortStart: 0,
		HostPortEnd:   0,
		ContainerPort: 5432,
		Protocol:      "tcp",
	}

	// Case A: container == nil -> no match
	if ephemeral.MatchesContainerPort(5432, nil) {
		t.Errorf("Case A: ephemeral port must NOT match when container is nil")
	}

	// Case A2: container with no ports -> no match
	emptyContainer := &domain.Container{}
	if ephemeral.MatchesContainerPort(5432, emptyContainer) {
		t.Errorf("Case A2: ephemeral port must NOT match when container has no ports")
	}

	// Case B: Docker mapping HostPort=49153, ContainerPort=5432, Query=49153 -> MATCH
	containerB := &domain.Container{
		Ports: []domain.PortMapping{
			{HostIP: "0.0.0.0", HostPort: 49153, ContainerPort: 5432, Protocol: "tcp"},
		},
	}
	if !ephemeral.MatchesContainerPort(49153, containerB) {
		t.Errorf("Case B: ephemeral port 5432 should match hostPort 49153 via Docker mapping")
	}
	// Querying 5432 against containerB must not match
	if ephemeral.MatchesContainerPort(5432, containerB) {
		t.Errorf("Case B: ephemeral port 5432 must NOT match hostPort 5432 when Docker mapped 49153")
	}

	// Case C: Docker mapping HostPort=49153, ContainerPort=3306, Query=49153 -> NO MATCH
	containerC := &domain.Container{
		Ports: []domain.PortMapping{
			{HostIP: "0.0.0.0", HostPort: 49153, ContainerPort: 3306, Protocol: "tcp"},
		},
	}
	if ephemeral.MatchesContainerPort(49153, containerC) {
		t.Errorf("Case C: ephemeral port 5432 must NOT match when Docker mapped containerPort 3306")
	}
}
