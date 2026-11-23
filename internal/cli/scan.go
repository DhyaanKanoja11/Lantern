package cli

import (
	"fmt"
	"os"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/spf13/cobra"
)

var (
	scanFailOnWildcard bool
	scanIgnorePorts    []int
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
		if err := formatter.RenderScan(cmd.OutOrStdout(), report.Summaries, report.Notices...); err != nil {
			return err
		}

		if scanFailOnWildcard {
			if violations := evaluateWildcardViolations(report.Summaries, scanIgnorePorts); len(violations) > 0 {
				isCI := os.Getenv("GITHUB_ACTIONS") == "true"
				for _, v := range violations {
					name := v.ProcessName
					if v.ContainerName != "" {
						name = fmt.Sprintf("%s (container: %s)", v.ProcessName, v.ContainerName)
					}
					if isCI {
						fmt.Fprintf(cmd.ErrOrStderr(), "::error title=Wildcard Port Exposure::Port %d (%s) is bound to wildcard address %s\n", v.Port, name, v.Address)
					}
				}
				return fmt.Errorf("wildcard port exposure policy violation: %d service(s) bound to wildcard address (0.0.0.0 or ::)", len(violations))
			}
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&scanFailOnWildcard, "fail-on-wildcard", false, "Fail with non-zero exit code if any service is bound to a wildcard address (0.0.0.0 or ::)")
	scanCmd.Flags().IntSliceVar(&scanIgnorePorts, "ignore-ports", nil, "Comma-separated list of ports to ignore for failure checks (e.g. 80,443)")
}

func evaluateWildcardViolations(summaries []domain.ExposureSummary, ignorePorts []int) []domain.ExposureSummary {
	ignored := make(map[uint16]bool, len(ignorePorts))
	for _, p := range ignorePorts {
		if p > 0 && p <= 65535 {
			ignored[uint16(p)] = true
		}
	}

	var violations []domain.ExposureSummary
	for _, s := range summaries {
		if ignored[s.Port] {
			continue
		}
		if isWildcardAddress(s.Address) {
			violations = append(violations, s)
		}
	}
	return violations
}

func isWildcardAddress(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "*" || addr == "[::]" || addr == "0:0:0:0:0:0:0:0"
}
