package collector

import (
	"strings"
	"testing"
)

func TestParseWindowsNetstat_ValidOutput(t *testing.T) {
	sample := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       6620
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       22372
  TCP    [::]:135               [::]:0                 LISTENING       2200
  TCP    127.0.0.1:50108        127.0.0.1:58050        TIME_WAIT       0
  TCP    172.25.212.71:49473    4.213.25.241:443       ESTABLISHED     2400
`

	listeners, err := ParseWindowsNetstat(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("unexpected netstat parse error: %v", err)
	}

	if len(listeners) != 4 {
		t.Fatalf("expected 4 listening sockets, got %d: %+v", len(listeners), listeners)
	}

	// First should be port 22
	if listeners[0].Port != 22 || listeners[0].Address != "0.0.0.0" || listeners[0].PID != 6620 {
		t.Errorf("unexpected entry 0: %+v", listeners[0])
	}

	// Port 135 ([::] -> ::)
	if listeners[1].Port != 135 || listeners[1].Address != "::" || listeners[1].PID != 2200 {
		t.Errorf("unexpected entry 1: %+v", listeners[1])
	}

	// Port 445
	if listeners[2].Port != 445 || listeners[2].Address != "0.0.0.0" || listeners[2].PID != 4 {
		t.Errorf("unexpected entry 2: %+v", listeners[2])
	}

	// Port 11434
	if listeners[3].Port != 11434 || listeners[3].Address != "127.0.0.1" || listeners[3].PID != 22372 {
		t.Errorf("unexpected entry 3: %+v", listeners[3])
	}
}

func TestParseWindowsNetstat_EmptyOrMalformed(t *testing.T) {
	listeners, err := ParseWindowsNetstat(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners for empty input, got %d", len(listeners))
	}

	malformed := `
Random garbage
Proto Local Foreign State PID
UDP   0.0.0.0:123 *:0 4
`
	listeners, err = ParseWindowsNetstat(strings.NewReader(malformed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(listeners))
	}
}

func TestParseWindowsNetstat_UDP(t *testing.T) {
	sample := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  UDP    0.0.0.0:123            *:*                                    10400
  UDP    127.0.0.1:5353         *:*                                    24084
  UDP    0.0.0.0:56399          192.178.211.84:443                     25908
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       6620
`

	listeners, err := ParseWindowsNetstat(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("unexpected netstat parse error: %v", err)
	}

	// Connected UDP socket on 56399 is excluded, so 3 listeners: TCP 22, UDP 123, UDP 5353
	if len(listeners) != 3 {
		t.Fatalf("expected 3 listening sockets, got %d: %+v", len(listeners), listeners)
	}

	if listeners[0].Port != 22 || listeners[0].Protocol != "tcp" {
		t.Errorf("expected entry 0 to be tcp:22, got %+v", listeners[0])
	}
	if listeners[1].Port != 123 || listeners[1].Protocol != "udp" || listeners[1].PID != 10400 {
		t.Errorf("expected entry 1 to be udp:123, got %+v", listeners[1])
	}
	if listeners[2].Port != 5353 || listeners[2].Protocol != "udp" || listeners[2].PID != 24084 {
		t.Errorf("expected entry 2 to be udp:5353, got %+v", listeners[2])
	}
}
