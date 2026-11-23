package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/DhyaanKanoja11/Lantern/internal/policy"
	"github.com/spf13/cobra"
)

var (
	scanFailOnWildcard bool
	scanIgnorePorts    []int
	scanWatch          bool
	scanInterval       time.Duration
	scanConfigFile     string
	scanFormat         string
	scanJSON           bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Discover TCP listening services",
	RunE: func(cmd *cobra.Command, args []string) error {
		var cfg *policy.Config
		var err error

		if scanConfigFile != "" {
			cfg, err = policy.LoadFile(scanConfigFile)
			if err != nil {
				return err
			}
		} else {
			cfg, _, err = policy.FindAndLoad("")
			if err != nil {
				return err
			}
		}

		flagFailChanged := cmd.Flags().Changed("fail-on-wildcard")
		effectiveFail, effectiveIgnore := cfg.MergeWithFlags(scanFailOnWildcard, flagFailChanged, scanIgnorePorts)

		analyzer := exposure.NewDefaultAnalyzer()
		format := strings.ToLower(scanFormat)
		if scanJSON {
			format = "json"
		}

		var formatter output.Formatter
		switch format {
		case "text", "":
			formatter = output.NewTextFormatter()
		case "json":
			formatter = output.NewJSONFormatter()
		case "sarif":
			formatter = output.NewSarifFormatter(Version)
		default:
			return fmt.Errorf("unsupported output format %q: must be one of text, json, sarif", scanFormat)
		}

		if scanWatch {
			textFormatter, ok := formatter.(*output.TextFormatter)
			if !ok {
				textFormatter = output.NewTextFormatter()
			}
			return runScanWatch(cmd.Context(), cmd, analyzer, textFormatter, scanInterval, effectiveFail, effectiveIgnore)
		}

		return runScanOnce(cmd.Context(), cmd, analyzer, formatter, effectiveFail, effectiveIgnore)
	},
}

func runScanOnce(ctx context.Context, cmd *cobra.Command, analyzer exposure.Analyzer, formatter output.Formatter, failOnWildcard bool, ignorePorts []int) error {
	report, err := analyzer.ScanReport(ctx)
	if err != nil {
		return err
	}

	if err := formatter.RenderScan(cmd.OutOrStdout(), report.Summaries, report.Notices...); err != nil {
		return err
	}

	violations := evaluateWildcardViolations(report.Summaries, ignorePorts)
	if os.Getenv("GITHUB_STEP_SUMMARY") != "" {
		writeGitHubStepSummary(report.Summaries, violations, ignorePorts)
	}

	if failOnWildcard && len(violations) > 0 {
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

	return nil
}

func writeGitHubStepSummary(summaries []domain.ExposureSummary, violations []domain.ExposureSummary, ignorePorts []int) {
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryPath == "" {
		return
	}

	ignoredMap := make(map[uint16]bool, len(ignorePorts))
	for _, p := range ignorePorts {
		if p > 0 && p <= 65535 {
			ignoredMap[uint16(p)] = true
		}
	}

	var sb strings.Builder
	sb.WriteString("### 🛡️ Lantern Port Exposure Report\n\n")

	if len(summaries) == 0 {
		sb.WriteString("No active listening TCP sockets detected.\n")
	} else {
		sb.WriteString("| Port | Proto | Bind Address | Service / Container | Reachability | Status |\n")
		sb.WriteString("| :---: | :---: | :---: | :--- | :--- | :---: |\n")
		for _, s := range summaries {
			target := s.ProcessName
			if s.ContainerName != "" {
				target = fmt.Sprintf("%s (`%s`)", s.ProcessName, s.ContainerName)
			}
			if target == "" {
				target = "-"
			}

			status := "✅ Clean"
			if isWildcardAddress(s.Address) {
				if ignoredMap[s.Port] {
					status = "⚪ *Whitelisted*"
				} else {
					status = "❌ **Violation**"
				}
			}

			sb.WriteString(fmt.Sprintf("| `%d` | %s | `%s` | %s | %s | %s |\n",
				s.Port, s.Protocol, s.Address, target, s.Reachability, status))
		}
	}

	if len(violations) > 0 {
		sb.WriteString(fmt.Sprintf("\n> ⚠️ **%d wildcard exposure policy violation(s) detected.** Run `lantern why <port>` or `lantern fix <port>` to remediate.\n", len(violations)))
	} else {
		sb.WriteString("\n> ✅ All active network listeners comply with security policy.\n")
	}

	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(sb.String())
	}
}

func runScanWatch(ctx context.Context, cmd *cobra.Command, analyzer exposure.Analyzer, formatter *output.TextFormatter, interval time.Duration, failOnWildcard bool, ignorePorts []int) error {
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	out := cmd.OutOrStdout()

	scanIteration := func() error {
		// ANSI escape sequence: clear screen and move cursor to top-left
		fmt.Fprint(out, "\033[H\033[2J")
		nowStr := time.Now().Format("2006-01-02 15:04:05")
		fmt.Fprintf(out, "Lantern Watch Mode — Scanning every %s (Ctrl+C to quit)\n", interval)
		fmt.Fprintf(out, "Last refresh: %s\n\n", nowStr)

		report, err := analyzer.ScanReport(ctx)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Scan error: %v\n", err)
			return nil
		}

		if err := formatter.RenderScan(out, report.Summaries, report.Notices...); err != nil {
			return err
		}

		if failOnWildcard {
			violations := evaluateWildcardViolations(report.Summaries, ignorePorts)
			if len(violations) > 0 {
				fmt.Fprintln(out)
				fmt.Fprintf(out, " [ALERT] %d wildcard exposure(s) active:\n", len(violations))
				for _, v := range violations {
					name := v.ProcessName
					if v.ContainerName != "" {
						name = fmt.Sprintf("%s (container: %s)", v.ProcessName, v.ContainerName)
					}
					fmt.Fprintf(out, "   -> Port %d (%s) on %s\n", v.Port, name, v.Address)
				}
			}
		}
		return nil
	}

	if err := scanIteration(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out, "\nWatch mode stopped.")
			return nil
		case <-sigChan:
			fmt.Fprintln(out, "\nWatch mode interrupted. Exiting cleanly.")
			return nil
		case <-ticker.C:
			if err := scanIteration(); err != nil {
				return err
			}
		}
	}
}

func init() {
	scanCmd.Flags().BoolVar(&scanFailOnWildcard, "fail-on-wildcard", false, "Fail with non-zero exit code if any service is bound to a wildcard address (0.0.0.0 or ::)")
	scanCmd.Flags().IntSliceVar(&scanIgnorePorts, "ignore-ports", nil, "Comma-separated list of ports to ignore for failure checks (e.g. 80,443)")
	scanCmd.Flags().BoolVarP(&scanWatch, "watch", "w", false, "Continuously monitor and refresh active network listeners")
	scanCmd.Flags().DurationVar(&scanInterval, "interval", 2*time.Second, "Refresh interval in watch mode (e.g. 2s, 5s)")
	scanCmd.Flags().StringVarP(&scanConfigFile, "config", "c", "", "Path to .lantern.yaml policy configuration file")
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "text", "Output format: text, json, sarif")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output results as JSON (alias for --format json)")
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
