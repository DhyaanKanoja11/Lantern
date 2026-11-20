package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Release metadata variables populated at build time via -ldflags.
var (
	Version = "v0.2.1"
	Commit  = "none"
	Date    = "unknown"
)

// FormatVersion returns the formatted version string.
func FormatVersion() string {
	if Commit != "" && Commit != "none" {
		return fmt.Sprintf("lantern %s (commit: %s, built: %s, %s/%s)", Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("lantern %s", Version)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Lantern",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(FormatVersion())
	},
}
