package network

import (
	"os"
	"runtime"
	"strings"
)

// ipv6WildcardDualStack reports whether a socket bound to :: also accepts
// IPv4 connections. It's a variable so tests can pin the answer.
//
// On Linux we read net.ipv6.bindv6only (default 0, i.e. dual-stack). An
// application can still set IPV6_V6ONLY on its own socket, which we can't
// see from here, so when in doubt we assume dual-stack: overstating
// exposure is the safe mistake. Go programs, for example, listen dual-stack
// on every OS.
var ipv6WildcardDualStack = func() bool {
	if runtime.GOOS != "linux" {
		return true
	}
	data, err := os.ReadFile("/proc/sys/net/ipv6/bindv6only")
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != "1"
}
