package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"lantern/internal/exposure"
	"lantern/internal/output"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Discover TCP listening services",
	RunE: func(cmd *cobra.Command, args []string) error {
		analyzer := exposure.NewDefaultAnalyzer()
		summaries, err := analyzer.Scan(cmd.Context())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", err)
			return nil
		}

		formatter := output.NewTextFormatter()
		return formatter.RenderScan(cmd.OutOrStdout(), summaries)
	},
}
