package collector

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ParseWindowsNetstat parses the standard stdout of 'netstat -ano -p tcp' on Windows.
func ParseWindowsNetstat(r io.Reader) ([]domain.Listener, error) {
	scanner := bufio.NewScanner(r)
	var listeners []domain.Listener

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		// Expected: Proto Local_Address Foreign_Address State PID
		if len(fields) < 5 {
			continue
		}

		if !strings.EqualFold(fields[0], "TCP") {
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
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}
