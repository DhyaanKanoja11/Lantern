//go:build !windows

package remediation

import (
	"os"
	"syscall"
)

// chown is a variable so tests can observe it without running as root.
var chown = os.Chown

// copyOwner makes dst owned by the same uid/gid as src's FileInfo. This
// matters when lantern runs under sudo: without it the rewritten compose file
// and its backup would end up owned by root.
func copyOwner(dst string, src os.FileInfo) error {
	st, ok := src.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return chown(dst, int(st.Uid), int(st.Gid))
}
