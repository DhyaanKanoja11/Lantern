//go:build windows

package remediation

import "os"

// copyOwner is a no-op on Windows; files inherit ACLs from their directory.
func copyOwner(dst string, src os.FileInfo) error { return nil }
