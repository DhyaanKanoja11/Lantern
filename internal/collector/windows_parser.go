package collector

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ParseWindowsNetstat parses the standard stdout of 'netstat -ano' on Windows for both TCP and UDP.
func ParseWindowsNetstat(r io.Reader) ([]domain.Listener, error) {
	scanner := bufio.NewScanner(r)
	var listeners []domain.Listener

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		switch proto {
		case "tcp":
			// Expected: TCP Local_Address Foreign_Address State PID
			if len(fields) < 5 {
				continue
			}

			// Windows netstat states: LISTENING, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.
			if !strings.EqualFold(fields[3], "LISTENING") {
				continue
			}

			addr, port, err := SplitAddressPort(fields[1])
			if err != nil {
				continue
			}

			pid, _ := strconv.Atoi(fields[4])

			listeners = append(listeners, domain.Listener{
				Protocol: "tcp",
				Address:  addr,
				Port:     port,
				PID:      pid,
			})

		case "udp":
			// Expected: UDP Local_Address Foreign_Address PID (State is omitted in netstat for UDP)
			if len(fields) < 4 {
				continue
			}

			foreign := fields[2]
			// Only include bound listening receivers (foreign address *:* or ending with :*)
			if foreign != "*:*" && !strings.HasSuffix(foreign, ":*") {
				continue
			}

			addr, port, err := SplitAddressPort(fields[1])
			if err != nil {
				continue
			}

			pid, _ := strconv.Atoi(fields[len(fields)-1])

			listeners = append(listeners, domain.Listener{
				Protocol: "udp",
				Address:  addr,
				Port:     port,
				PID:      pid,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}
