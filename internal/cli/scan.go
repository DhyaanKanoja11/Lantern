package cli

import (
	"github.com/spf13/cobra"
	"lantern/internal/exposure"
	"lantern/internal/output"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Discover TCP listening services",
	RunE: func(cmd *cobra.Command, args []string) error {
		analyzer := exposure.NewDefaultAnalyzer()
		report, err := analyzer.ScanReport(cmd.Context())
		if err != nil {
			return err
		}

		formatter := output.NewTextFormatter()
		return formatter.RenderScan(cmd.OutOrStdout(), report.Summaries, report.Notices...)
	},
}
