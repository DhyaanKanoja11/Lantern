package collector

import (
	"strings"
	"testing"
)

func TestParseDarwinLsof_ValidOutput(t *testing.T) {
	sample := `
COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd     1 root   11u  IPv4 0x867b7f6fa595d249      0t0  TCP *:22 (LISTEN)
node    48212 user   23u  IPv4 0x867b7f6fa595d989      0t0  TCP *:3000 (LISTEN)
postgres 1290 user    7u  IPv4 0x867b7f6fa595d123      0t0  TCP 127.0.0.1:5432 (LISTEN)
redis-se 2345 user    5u  IPv6 0x867b7f6fa595d999      0t0  TCP [::1]:6379 (LISTEN)
`

	listeners, err := ParseDarwinLsof(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("unexpected lsof parse error: %v", err)
	}

	if len(listeners) != 4 {
		t.Fatalf("expected 4 listening sockets, got %d: %+v", len(listeners), listeners)
	}

	// Port 22: *:22 -> normalized to 0.0.0.0
	if listeners[0].Port != 22 || listeners[0].Address != "0.0.0.0" || listeners[0].PID != 1 || listeners[0].ProcessName != "launchd" {
		t.Errorf("unexpected entry 0: %+v", listeners[0])
	}

	// Port 3000: node
	if listeners[1].Port != 3000 || listeners[1].Address != "0.0.0.0" || listeners[1].PID != 48212 || listeners[1].ProcessName != "node" {
		t.Errorf("unexpected entry 1: %+v", listeners[1])
	}

	// Port 5432: postgres
	if listeners[2].Port != 5432 || listeners[2].Address != "127.0.0.1" || listeners[2].PID != 1290 || listeners[2].ProcessName != "postgres" {
		t.Errorf("unexpected entry 2: %+v", listeners[2])
	}

	// Port 6379: redis-se on ::1
	if listeners[3].Port != 6379 || listeners[3].Address != "::1" || listeners[3].PID != 2345 || listeners[3].ProcessName != "redis-se" {
		t.Errorf("unexpected entry 3: %+v", listeners[3])
	}
}

func TestParseDarwinLsof_EmptyOrMalformed(t *testing.T) {
	listeners, err := ParseDarwinLsof(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(listeners))
	}
}

func TestParseDarwinLsof_UDP(t *testing.T) {
	sample := `
COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
mDNSRes   123 root   11u  IPv4 0x867b7f6fa595d249      0t0  UDP *:5353
dnsmasq   456 user    5u  IPv4 0x867b7f6fa595d111      0t0  UDP 127.0.0.1:53
client    999 user    7u  IPv4 0x867b7f6fa595d222      0t0  UDP 192.168.1.10:54321->8.8.8.8:53
node    48212 user   23u  IPv4 0x867b7f6fa595d989      0t0  TCP *:3000 (LISTEN)
`

	listeners, err := ParseDarwinLsof(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("unexpected lsof parse error: %v", err)
	}

	// Connected UDP socket on 54321 is skipped, so 3 listeners expected: 53 (UDP), 3000 (TCP), 5353 (UDP)
	if len(listeners) != 3 {
		t.Fatalf("expected 3 listening sockets, got %d: %+v", len(listeners), listeners)
	}

	if listeners[0].Port != 53 || listeners[0].Protocol != "udp" || listeners[0].ProcessName != "dnsmasq" {
		t.Errorf("unexpected entry 0: %+v", listeners[0])
	}
	if listeners[1].Port != 3000 || listeners[1].Protocol != "tcp" || listeners[1].ProcessName != "node" {
		t.Errorf("unexpected entry 1: %+v", listeners[1])
	}
	if listeners[2].Port != 5353 || listeners[2].Protocol != "udp" || listeners[2].ProcessName != "mDNSRes" {
		t.Errorf("unexpected entry 2: %+v", listeners[2])
	}
}
