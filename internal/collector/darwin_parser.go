package collector

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ParseDarwinLsof parses the standard stdout of 'lsof -iTCP -sTCP:LISTEN -P -n' on macOS.
// Example line:
// COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
// node    48212 user   23u  IPv4 0x867b7f6fa595d989      0t0  TCP *:3000 (LISTEN)
// postgres 1290 user    7u  IPv4 0x867b7f6fa595d123      0t0  TCP 127.0.0.1:5432 (LISTEN)
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

		// Find the target address:port token. In lsof it is usually the field after "TCP"
		var addrToken string
		for i, f := range fields {
			if strings.EqualFold(f, "TCP") && i+1 < len(fields) {
				addrToken = fields[i+1]
				break
			}
		}

		if addrToken == "" {
			// Fallback: look for token with a colon that doesn't say LISTEN
			for _, f := range fields {
				if strings.Contains(f, ":") && !strings.Contains(f, "LISTEN") {
					addrToken = f
					break
				}
			}
		}

		if addrToken == "" {
			continue
		}

		addr, port, err := SplitAddressPort(addrToken)
		if err != nil {
			continue
		}

		listeners = append(listeners, domain.Listener{
			Protocol:    "tcp",
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
