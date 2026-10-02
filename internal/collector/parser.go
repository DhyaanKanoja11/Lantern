package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"lantern/internal/domain"
)

// NormalizeAddress cleans and standardizes IPv4 and IPv6 representation.
func NormalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "[]")

	if addr == "" || addr == "*" || addr == "0.0.0.0" {
		return "0.0.0.0"
	}
	if addr == "::" || addr == "*:*" {
		return "::"
	}
	if addr == "::1" {
		return "::1"
	}
	if addr == "127.0.0.1" {
		return "127.0.0.1"
	}

	// Normalize IPv4-mapped IPv6 addresses, e.g. ::ffff:127.0.0.1 -> 127.0.0.1
	if strings.HasPrefix(strings.ToLower(addr), "::ffff:") {
		mapped := addr[7:]
		if net.ParseIP(mapped) != nil {
			return mapped
		}
	}

	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}

	return addr
}

// SplitAddressPort extracts normalized host and port from a string like "0.0.0.0:22" or "[::]:22".
func SplitAddressPort(s string) (string, uint16, error) {
	s = strings.TrimSpace(s)
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return "", 0, fmt.Errorf("missing port delimiter in %q", s)
	}

	hostPart := s[:lastColon]
	portPart := s[lastColon+1:]

	portNum, err := strconv.ParseUint(portPart, 10, 16)
	if err != nil || portNum == 0 {
		return "", 0, fmt.Errorf("invalid port in %q: %w", s, err)
	}

	return NormalizeAddress(hostPart), uint16(portNum), nil
}

// ParseSSUsers extracts process name and PID from `users:(("name",pid=123,fd=4))` section.
func ParseSSUsers(line string) (string, int) {
	idx := strings.Index(line, "users:(")
	if idx == -1 {
		return "", 0
	}
	sub := line[idx:]

	var name string
	var pid int

	// Extract process name
	if quoteStart := strings.Index(sub, `("`); quoteStart != -1 {
		rest := sub[quoteStart+2:]
		if quoteEnd := strings.Index(rest, `"`); quoteEnd != -1 {
			name = rest[:quoteEnd]
		}
	}

	// Extract PID
	if pidIdx := strings.Index(sub, "pid="); pidIdx != -1 {
		rest := sub[pidIdx+4:]
		var digits []byte
		for i := 0; i < len(rest); i++ {
			if rest[i] >= '0' && rest[i] <= '9' {
				digits = append(digits, rest[i])
			} else {
				break
			}
		}
		if len(digits) > 0 {
			pid, _ = strconv.Atoi(string(digits))
		}
	}

	return name, pid
}

// ParseSSLine parses a single line of `ss -lntpH` output into a Listener.
func ParseSSLine(line string) (*domain.Listener, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Skip header lines if present (e.g. if -H was omitted)
	if strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
		return nil, nil
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil, fmt.Errorf("insufficient fields in line: %q", line)
	}

	// The first field should be LISTEN
	if fields[0] != "LISTEN" {
		return nil, nil
	}

	// Local Address:Port is column 3 (0-indexed)
	localAddrStr := fields[3]
	addr, port, err := SplitAddressPort(localAddrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local address %q: %w", localAddrStr, err)
	}

	procName, pid := ParseSSUsers(line)

	return &domain.Listener{
		Protocol:    "tcp",
		Address:     addr,
		Port:        port,
		PID:         pid,
		ProcessName: procName,
	}, nil
}

// ParseSSOutput parses entire `ss -lntpH` output.
func ParseSSOutput(r io.Reader) ([]domain.Listener, error) {
	var listeners []domain.Listener
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		l, err := ParseSSLine(scanner.Text())
		if err != nil {
			// Skip malformed line without failing whole collection
			continue
		}
		if l != nil {
			listeners = append(listeners, *l)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}

// ParseProcNetTCP parses Linux /proc/net/tcp format.
func ParseProcNetTCP(r io.Reader) ([]domain.Listener, error) {
	var listeners []domain.Listener
	scanner := bufio.NewScanner(r)
	isHeader := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if isHeader {
			isHeader = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Field 3 is connection state. "0A" is TCP_LISTEN in hex.
		if fields[3] != "0A" {
			continue
		}

		// Field 1 is local_address "XXXXXXXX:YYYY"
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}

		portHex, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			continue
		}

		ipBytes, err := hex.DecodeString(parts[0])
		if err != nil || len(ipBytes) != 4 {
			continue
		}

		// /proc/net/tcp encodes IPv4 in little-endian byte order
		ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()

		listeners = append(listeners, domain.Listener{
			Protocol:    "tcp",
			Address:     NormalizeAddress(ip),
			Port:        uint16(portHex),
			PID:         0,
			ProcessName: "",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}

// ParseProcNetTCP6 parses Linux /proc/net/tcp6 format.
func ParseProcNetTCP6(r io.Reader) ([]domain.Listener, error) {
	var listeners []domain.Listener
	scanner := bufio.NewScanner(r)
	isHeader := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if isHeader {
			isHeader = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		if fields[3] != "0A" {
			continue
		}

		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}

		portHex, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			continue
		}

		hexStr := parts[0]
		if len(hexStr) != 32 {
			continue
		}

		// /proc/net/tcp6 encodes IPv6 in 4 32-bit little-endian words
		ipBytes := make([]byte, 16)
		for word := 0; word < 4; word++ {
			chunk, err := hex.DecodeString(hexStr[word*8 : (word+1)*8])
			if err != nil || len(chunk) != 4 {
				break
			}
			ipBytes[word*4+0] = chunk[3]
			ipBytes[word*4+1] = chunk[2]
			ipBytes[word*4+2] = chunk[1]
			ipBytes[word*4+3] = chunk[0]
		}

		ip := net.IP(ipBytes)
		var addrStr string
		if v4 := ip.To4(); v4 != nil {
			addrStr = v4.String()
		} else {
			addrStr = ip.String()
		}

		listeners = append(listeners, domain.Listener{
			Protocol:    "tcp",
			Address:     NormalizeAddress(addrStr),
			Port:        uint16(portHex),
			PID:         0,
			ProcessName: "",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return DeduplicateAndSort(listeners), nil
}

// DeduplicateAndSort eliminates identical listener entries and sorts by Port then Address.
func DeduplicateAndSort(listeners []domain.Listener) []domain.Listener {
	seen := make(map[string]domain.Listener)

	for _, l := range listeners {
		key := fmt.Sprintf("%s:%d:%s", l.Address, l.Port, l.Protocol)
		existing, ok := seen[key]
		if !ok {
			seen[key] = l
			continue
		}
		// Prefer the entry that has process info
		if existing.ProcessName == "" && l.ProcessName != "" {
			seen[key] = l
		}
	}

	result := make([]domain.Listener, 0, len(seen))
	for _, l := range seen {
		result = append(result, l)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Address < result[j].Address
	})

	return result
}
