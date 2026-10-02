package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "v0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Lantern",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("lantern %s\n", Version)
	},
}
