package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lantern",
	Short: "Lantern explains why a network service is reachable",
	Long:  "Lantern is a local-first developer security tool that explains why a network service is reachable.",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(whyCmd)
}
