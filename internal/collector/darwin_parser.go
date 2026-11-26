package collector

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ParseDarwinLsof parses the standard stdout of 'lsof -iTCP -sTCP:LISTEN -P -n' and 'lsof -iUDP -P -n' on macOS.
func ParseDarwinLsof(r io.Reader) ([]domain.Listener, error) {
	scanner := bufio.NewScanner(r)
	var listeners []domain.Listener

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		command := fields[0]
		pidVal, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		// Find the target address:port token and protocol
		var proto string
		var addrToken string
		for i, f := range fields {
			if strings.EqualFold(f, "TCP") && i+1 < len(fields) {
				proto = "tcp"
				addrToken = fields[i+1]
				break
			}
			if strings.EqualFold(f, "UDP") && i+1 < len(fields) {
				proto = "udp"
				addrToken = fields[i+1]
				break
			}
		}

		if addrToken == "" {
			// Fallback: look for token with a colon that doesn't say LISTEN and is not connected
			for _, f := range fields {
				if strings.Contains(f, ":") && !strings.Contains(f, "LISTEN") && !strings.Contains(f, "->") {
					addrToken = f
					break
				}
			}
		}

		if addrToken == "" {
			continue
		}

		// For UDP, skip outbound connected datagram sockets (e.g. host:port->peer:port)
		if strings.Contains(addrToken, "->") {
			continue
		}

		// For TCP, ensure LISTEN state
		if proto == "tcp" && !strings.Contains(line, "LISTEN") {
			continue
		}
		if proto == "" {
			if strings.Contains(line, "LISTEN") {
				proto = "tcp"
			} else {
				proto = "udp"
			}
		}

		addr, port, err := SplitAddressPort(addrToken)
		if err != nil {
			continue
		}

		listeners = append(listeners, domain.Listener{
			Protocol:    proto,
			Address:     addr,
			Port:        port,
			PID:         pidVal,
			ProcessName: command,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}
