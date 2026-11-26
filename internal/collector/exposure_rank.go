package collector

import (
	"net"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// ExposureRank orders bind addresses by how much of the network can reach
// them: wildcard > specific non-loopback > loopback.
func ExposureRank(addr string) int {
	a := strings.Trim(strings.TrimSpace(addr), "[]")
	if i := strings.Index(a, "%"); i != -1 {
		a = a[:i]
	}
	if a == "" || a == "*" {
		return 2
	}
	ip := net.ParseIP(a)
	switch {
	case ip == nil:
		// Unknown format; assume the worst.
		return 2
	case ip.IsUnspecified():
		return 2
	case ip.IsLoopback():
		return 0
	default:
		return 1
	}
}

func exposureRank(addr string) int {
	return ExposureRank(addr)
}

// MostExposed returns the listener whose bind address is reachable from the
// most places. On ties the earliest one wins, so results stay stable.
// Panics on an empty slice, same as indexing would.
func MostExposed(listeners []domain.Listener) domain.Listener {
	best := listeners[0]
	for _, l := range listeners[1:] {
		if exposureRank(l.Address) > exposureRank(best.Address) {
			best = l
		}
	}
	return best
}

// findMostExposedOnPort is the shared implementation of FindListenerByPort.
func findMostExposedOnPort(listeners []domain.Listener, port uint16) *domain.Listener {
	var onPort []domain.Listener
	for _, l := range listeners {
		if l.Port == port {
			onPort = append(onPort, l)
		}
	}
	if len(onPort) == 0 {
		return nil
	}
	l := MostExposed(onPort)
	return &l
}
