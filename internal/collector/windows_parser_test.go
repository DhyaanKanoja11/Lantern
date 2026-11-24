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
