package cli

import (
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/spf13/cobra"
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
