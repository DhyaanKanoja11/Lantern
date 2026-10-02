package collector

import (
	"strings"
	"testing"

	"lantern/internal/domain"
)

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "0.0.0.0"},
		{"*", "0.0.0.0"},
		{"0.0.0.0", "0.0.0.0"},
		{"[0.0.0.0]", "0.0.0.0"},
		{"::", "::"},
		{"[::]", "::"},
		{"*:*", "::"},
		{"::1", "::1"},
		{"[::1]", "::1"},
		{"127.0.0.1", "127.0.0.1"},
		{"[127.0.0.1]", "127.0.0.1"},
		{"192.168.1.100", "192.168.1.100"},
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"[::ffff:127.0.0.1]", "127.0.0.1"},
		{"::ffff:192.168.1.5", "192.168.1.5"},
		{"fe80::1", "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeAddress(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSplitAddressPort(t *testing.T) {
	tests := []struct {
		input        string
		expectedAddr string
		expectedPort uint16
		shouldErr    bool
	}{
		{"0.0.0.0:22", "0.0.0.0", 22, false},
		{"127.0.0.1:3000", "127.0.0.1", 3000, false},
		{"[::]:22", "::", 22, false},
		{"[::1]:5432", "::1", 5432, false},
		{"*:80", "0.0.0.0", 80, false},
		{"[::ffff:127.0.0.1]:8080", "127.0.0.1", 8080, false},
		{"192.168.1.254:65535", "192.168.1.254", 65535, false},
		{"invalid-no-port", "", 0, true},
		{"127.0.0.1:0", "", 0, true},
		{"127.0.0.1:notaport", "", 0, true},
		{"127.0.0.1:99999", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			addr, port, err := SplitAddressPort(tt.input)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("SplitAddressPort(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("SplitAddressPort(%q) unexpected error: %v", tt.input, err)
			}
			if addr != tt.expectedAddr || port != tt.expectedPort {
				t.Errorf("SplitAddressPort(%q) = (%q, %d), want (%q, %d)",
					tt.input, addr, port, tt.expectedAddr, tt.expectedPort)
			}
		})
	}
}

func TestParseSSUsers(t *testing.T) {
	tests := []struct {
		line         string
		expectedName string
		expectedPID  int
	}{
		{`users:(("sshd",pid=842,fd=3))`, "sshd", 842},
		{`users:(("docker-proxy",pid=1234,fd=4))`, "docker-proxy", 1234},
		{`users:(("node",pid=1423,fd=19),("worker",pid=1424,fd=20))`, "node", 1423},
		{`users:(("my app with spaces",pid=999,fd=5))`, "my app with spaces", 999},
		{`no users column present`, "", 0},
		{`users:(("invalid",no_pid))`, "invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, pid := ParseSSUsers(tt.line)
			if name != tt.expectedName || pid != tt.expectedPID {
				t.Errorf("ParseSSUsers(%q) = (%q, %d), want (%q, %d)",
					tt.line, name, pid, tt.expectedName, tt.expectedPID)
			}
		})
	}
}

func TestParseSSOutput(t *testing.T) {
	fixture := `
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=842,fd=3))
LISTEN 0      511        127.0.0.1:3000      0.0.0.0:*    users:(("node",pid=1423,fd=19))
LISTEN 0      128          0.0.0.0:5432      0.0.0.0:*    users:(("postgres",pid=912,fd=5))
LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=842,fd=4))
LISTEN 0      128                *:80              *:*    users:(("nginx",pid=501,fd=6))
LISTEN 0      128                *:443             *:*
ESTAB  0      0       192.168.1.10:22   192.168.1.5:54321 users:(("sshd",pid=842,fd=5))
malformed line without fields
LISTEN 0      10     192.168.1.100:8080      0.0.0.0:*    users:(("app",pid=3210,fd=7))
`

	listeners, err := ParseSSOutput(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("unexpected error parsing SS output: %v", err)
	}

	// Expected valid LISTEN entries:
	// 22 (0.0.0.0), 22 (::), 80 (0.0.0.0), 443 (0.0.0.0), 3000 (127.0.0.1), 5432 (0.0.0.0), 8080 (192.168.1.100)
	if len(listeners) != 7 {
		t.Fatalf("expected 7 listeners, got %d", len(listeners))
	}

	// Verify specific parsed items
	found := make(map[uint16]string)
	for _, l := range listeners {
		found[l.Port] = l.ProcessName
		if l.Protocol != "tcp" {
			t.Errorf("listener on port %d has protocol %q, want tcp", l.Port, l.Protocol)
		}
	}

	if found[22] != "sshd" {
		t.Errorf("port 22 process = %q, want sshd", found[22])
	}
	if found[3000] != "node" {
		t.Errorf("port 3000 process = %q, want node", found[3000])
	}
	if found[5432] != "postgres" {
		t.Errorf("port 5432 process = %q, want postgres", found[5432])
	}
	if found[80] != "nginx" {
		t.Errorf("port 80 process = %q, want nginx", found[80])
	}
	// Port 443 had no process column
	if found[443] != "" {
		t.Errorf("port 443 process = %q, want empty (unprivileged/unknown)", found[443])
	}
}

func TestParseProcNetTCP(t *testing.T) {
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0101A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
   3: 0100007F:0016 0100007F:04D2 01 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0
`

	listeners, err := ParseProcNetTCP(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("unexpected error parsing /proc/net/tcp: %v", err)
	}

	// Entry 3 is st=01 (established), so only 3 listeners expected
	if len(listeners) != 3 {
		t.Fatalf("expected 3 listeners, got %d", len(listeners))
	}

	// 0100007F:0016 -> 127.0.0.1:22
	// 00000000:1538 -> 0.0.0.0:5432
	// 0101A8C0:1F90 -> 192.168.1.1:8080 (01=1, 01=1, A8=168, C0=192)
	expectedMap := map[uint16]string{
		22:   "127.0.0.1",
		5432: "0.0.0.0",
		8080: "192.168.1.1",
	}

	for _, l := range listeners {
		expAddr, ok := expectedMap[l.Port]
		if !ok {
			t.Errorf("unexpected port %d found", l.Port)
			continue
		}
		if l.Address != expAddr {
			t.Errorf("port %d: expected address %q, got %q", l.Port, expAddr, l.Address)
		}
		// PID and process should be 0 and empty
		if l.PID != 0 || l.ProcessName != "" {
			t.Errorf("port %d: expected PID 0 and empty process, got PID=%d, name=%q", l.Port, l.PID, l.ProcessName)
		}
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	fixture := `  sl  local_address                         rem_address                            st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000001000000:0BB8 00000000000000000000000001000000:1234 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
`

	listeners, err := ParseProcNetTCP6(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("unexpected error parsing /proc/net/tcp6: %v", err)
	}

	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}

	expectedMap := map[uint16]string{
		22:   "::",
		3000: "::1",
	}

	for _, l := range listeners {
		expAddr, ok := expectedMap[l.Port]
		if !ok {
			t.Errorf("unexpected port %d found", l.Port)
			continue
		}
		if l.Address != expAddr {
			t.Errorf("port %d: expected address %q, got %q", l.Port, expAddr, l.Address)
		}
	}
}

func TestDeduplicateAndSort(t *testing.T) {
	input := []domain.Listener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, ProcessName: ""},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, ProcessName: "postgres", PID: 912},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 3000, ProcessName: "node", PID: 100},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22, ProcessName: "sshd", PID: 50},
	}

	result := DeduplicateAndSort(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 listeners after deduplication, got %d", len(result))
	}

	// Should be sorted by port: 22, 3000, 5432
	if result[0].Port != 22 || result[1].Port != 3000 || result[2].Port != 5432 {
		t.Errorf("incorrect sort order: %+v", result)
	}

	// Port 5432 should have retained "postgres" process name
	if result[2].ProcessName != "postgres" {
		t.Errorf("expected port 5432 process 'postgres', got %q", result[2].ProcessName)
	}
}
