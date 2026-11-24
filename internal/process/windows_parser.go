package process

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ParseTasklistCSV parses CSV output of 'tasklist /FI "PID eq <pid>" /FO CSV /NH'.
// Example output: "ollama.exe","22372","Console","1","50,152 K"
func ParseTasklistCSV(r io.Reader, pid int) (*domain.Process, error) {
	reader := csv.NewReader(r)
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(record) == 0 {
			continue
		}

		// When no task matches, tasklist outputs: INFO: No tasks are running which match the specified criteria.
		if strings.HasPrefix(record[0], "INFO:") {
			return nil, fmt.Errorf("process %d does not exist (may have exited)", pid)
		}

		imageName := strings.TrimSpace(record[0])
		return &domain.Process{
			PID:  pid,
			Name: imageName,
		}, nil
	}

	return nil, fmt.Errorf("process %d not found", pid)
}
