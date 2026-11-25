package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DhyaanKanoja11/Lantern/internal/preflight"
	"github.com/spf13/cobra"
)

var (
	preflightJSONFlag bool
	preflightChecker  = preflight.NewChecker()
)

var preflightCmd = &cobra.Command{
	Use:   "preflight [path/to/compose.yaml]",
	Short: "Detect port clashes and wildcard exposures before running docker compose up",
	Long: `Lantern Preflight inspects your Docker Compose file against active host listening
sockets and internal port declarations before containers start.

Prevents "bind: address already in use" (EADDRINUSE) failures and detects silent wildcard
(0.0.0.0) exposures before running docker compose up.

Exit Codes:
  0: All clear (no collisions detected)
  1: File or syntax error
  2: Port collision detected (address already in use)`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := ""
		if len(args) > 0 {
			filePath = args[0]
		} else {
			// Auto-discover in current directory
			candidates := []string{
				"docker-compose.yml",
				"docker-compose.yaml",
				"compose.yml",
				"compose.yaml",
			}
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					filePath = c
					break
				}
			}
			if filePath == "" {
				return fmt.Errorf("no compose file specified and none found in current directory (looked for docker-compose.yml, compose.yaml)")
			}
		}

		report, err := preflightChecker.CheckFile(cmd.Context(), filePath)
		if err != nil {
			return err
		}

		if preflightJSONFlag {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(report); err != nil {
				return err
			}
		} else {
			renderPreflightReport(cmd, report)
		}

		if !report.Passed {
			return fmt.Errorf("preflight check failed: %d port collision(s) detected (resolve with 'lantern free <port>')", len(report.Collisions))
		}

		return nil
	},
}

func renderPreflightReport(cmd *cobra.Command, r *preflight.Report) {
	fmt.Fprintf(cmd.OutOrStdout(), "Lantern Preflight: %s\n", r.FilePath)
	fmt.Fprintf(cmd.OutOrStdout(), "Analyzed %d declared port mapping(s).\n\n", r.TotalPorts)

	if len(r.Collisions) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "[COLLISION DETECTED] %d port conflict(s) will block startup:\n", len(r.Collisions))
		for _, c := range r.Collisions {
			fmt.Fprintf(cmd.OutOrStdout(), "  - Port %d (%s, line %d):\n", c.Port, c.Service, c.Line)
			fmt.Fprintf(cmd.OutOrStdout(), "      Conflict: %s\n", c.OccupiedBy)
			if c.SuggestedPort > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "      Suggestion: change to port %d\n", c.SuggestedPort)
			}
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(r.Wildcards) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "[EXPOSURE WARNING] %d port(s) bind to wildcard (0.0.0.0):\n", len(r.Wildcards))
		for _, w := range r.Wildcards {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s (line %d): %s -> recommend %s\n", w.Service, w.Line, w.Original, w.SuggestedFix)
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}

	if r.Passed {
		fmt.Fprintln(cmd.OutOrStdout(), "[OK] All ports are available on the host. Safe to run docker compose up.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "[ABORT] Resolve port conflicts or run 'lantern free <port>' before starting containers.")
	}
}

func init() {
	preflightCmd.Flags().BoolVar(&preflightJSONFlag, "json", false, "Output preflight analysis as structured JSON")
}
