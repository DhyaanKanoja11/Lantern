package process

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// ParseComm cleans and returns the process name from /proc/<pid>/comm.
func ParseComm(data []byte) string {
	s := strings.TrimSpace(string(data))
	return strings.TrimRight(s, "\r\n")
}

// ParseCmdline decodes NUL-separated command-line arguments into a space-separated string.
// Note: It never reads or exposes environment variables.
func ParseCmdline(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	parts := bytes.Split(data, []byte{0})
	var args []string
	for _, p := range parts {
		if len(p) > 0 {
			args = append(args, string(p))
		}
	}

	return strings.Join(args, " ")
}

// ParseStatus extracts Name, PPid, and real Uid from /proc/<pid>/status.
func ParseStatus(data []byte) (name string, ppid int, uid int, hasPPID bool, hasUID bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "PPid:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if p, err := strconv.Atoi(val); err == nil {
				ppid = p
				hasPPID = true
			}
		} else if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if u, err := strconv.Atoi(fields[0]); err == nil {
					uid = u
					hasUID = true
				}
			}
		}
	}
	return
}

// ParseStat safely extracts PPID from /proc/<pid>/stat.
// It handles process names with spaces and nested parentheses.
func ParseStat(data []byte) (int, error) {
	s := strings.TrimSpace(string(data))
	rParen := strings.LastIndex(s, ")")
	if rParen == -1 {
		return 0, fmt.Errorf("malformed stat: missing closing parenthesis")
	}

	rest := s[rParen+1:]
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed stat: insufficient fields after comm")
	}

	// Field 0 after ')' is state, field 1 is PPID
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("invalid ppid %q in stat: %w", fields[1], err)
	}

	return ppid, nil
}
