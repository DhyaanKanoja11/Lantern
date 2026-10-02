package docker

import (
	"testing"
)

func TestParseContainerIDs(t *testing.T) {
	fixture := []byte("abc123456789\ndef987654321\n\n456789abcdef\n")
	ids := ParseContainerIDs(fixture)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	if ids[0] != "abc123456789" || ids[1] != "def987654321" || ids[2] != "456789abcdef" {
		t.Errorf("unexpected IDs: %+v", ids)
	}

	empty := ParseContainerIDs([]byte("\n  \n"))
	if len(empty) != 0 {
		t.Errorf("expected 0 IDs for empty input, got %d", len(empty))
	}
}

func TestParseInspectOutput_Valid(t *testing.T) {
	fixture := []byte(`[
		{
			"Id": "c1234567890abcdef",
			"Name": "/postgres-dev",
			"State": {
				"Status": "running",
				"Running": true,
				"Pid": 12345
			},
			"Config": {
				"Image": "postgres:16",
				"Labels": {
					"com.docker.compose.service": "db"
				}
			},
			"NetworkSettings": {
				"Networks": {
					"bridge": {}
				},
				"Ports": {
					"5432/tcp": [
						{
							"HostIp": "0.0.0.0",
							"HostPort": "5432"
						}
					],
					"53/udp": [
						{
							"HostIp": "127.0.0.1",
							"HostPort": "5353"
						}
					],
					"8080/tcp": [
						{
							"HostIp": "192.168.1.50",
							"HostPort": "80"
						}
					]
				}
			}
		}
	]`)

	containers, err := ParseInspectOutput(fixture)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	c := containers[0]
	if c.ID != "c1234567890abcdef" {
		t.Errorf("expected ID 'c1234567890abcdef', got %q", c.ID)
	}
	if c.Name != "postgres-dev" {
		t.Errorf("expected Name 'postgres-dev' (without slash), got %q", c.Name)
	}
	if c.Image != "postgres:16" {
		t.Errorf("expected Image 'postgres:16', got %q", c.Image)
	}
	if !c.Running {
		t.Errorf("expected Running true, got false")
	}
	if c.HostPID != 12345 {
		t.Errorf("expected HostPID 12345, got %d", c.HostPID)
	}
	if c.Labels["com.docker.compose.service"] != "db" {
		t.Errorf("missing or incorrect label: %+v", c.Labels)
	}
	if len(c.Networks) != 1 || c.Networks[0] != "bridge" {
		t.Errorf("unexpected networks: %+v", c.Networks)
	}

	// Verify multiple published ports: TCP, UDP, host IPs
	if len(c.Ports) != 3 {
		t.Fatalf("expected 3 port mappings, got %d: %+v", len(c.Ports), c.Ports)
	}

	portsMap := make(map[uint16]string)
	for _, p := range c.Ports {
		portsMap[p.HostPort] = p.Protocol + "@" + p.HostIP
	}

	if portsMap[5432] != "tcp@0.0.0.0" {
		t.Errorf("expected 5432 tcp@0.0.0.0, got %q", portsMap[5432])
	}
	if portsMap[5353] != "udp@127.0.0.1" {
		t.Errorf("expected 5353 udp@127.0.0.1, got %q", portsMap[5353])
	}
	if portsMap[80] != "tcp@192.168.1.50" {
		t.Errorf("expected 80 tcp@192.168.1.50, got %q", portsMap[80])
	}
}

func TestParseInspectOutput_NoHostPID(t *testing.T) {
	fixture := []byte(`[
		{
			"Id": "stopped123",
			"Name": "/stopped-container",
			"State": {
				"Status": "exited",
				"Running": false,
				"Pid": 0
			},
			"Config": {
				"Image": "alpine:latest"
			},
			"NetworkSettings": {
				"Ports": {}
			}
		}
	]`)

	containers, err := ParseInspectOutput(fixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	if containers[0].HostPID != 0 {
		t.Errorf("expected HostPID 0, got %d", containers[0].HostPID)
	}
	if containers[0].Running {
		t.Errorf("expected Running false, got true")
	}
}

func TestParseInspectOutput_Malformed(t *testing.T) {
	// 1. Invalid JSON
	_, err := ParseInspectOutput([]byte("not valid json at all"))
	if err == nil {
		t.Errorf("expected error for non-JSON, got nil")
	}

	// 2. Empty JSON
	empty, err := ParseInspectOutput([]byte(""))
	if err != nil || len(empty) != 0 {
		t.Errorf("expected empty slice without error for empty input")
	}

	// 3. Array containing one malformed element and one valid element
	mixed := []byte(`[
		{ "invalid": "structure without id" },
		{
			"Id": "valid123",
			"Name": "/valid",
			"State": { "Pid": 444 },
			"Config": { "Image": "redis:alpine" },
			"NetworkSettings": { "Ports": {} }
		}
	]`)

	containers, err := ParseInspectOutput(mixed)
	if err != nil {
		t.Fatalf("unexpected error parsing mixed array: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 valid container recovered, got %d", len(containers))
	}
	if containers[0].ID != "valid123" {
		t.Errorf("expected ID valid123, got %q", containers[0].ID)
	}
}
