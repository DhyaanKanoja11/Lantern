package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/preflight"
	"github.com/spf13/cobra"
)

var (
	preflightJSONFlag      bool
	preflightInstallHook   bool
	preflightUninstallHook bool
	preflightChecker       = preflight.NewChecker()
)

var preflightCmd = &cobra.Command{
	Use:   "preflight [path/to/compose.yaml ...]",
	Short: "Detect port clashes and wildcard exposures before running docker compose up",
	Long: `Lantern Preflight inspects your Docker Compose file(s) against active host listening
sockets and internal port declarations before containers start.

When a single file is provided or auto-discovered, any sibling override file
(such as docker-compose.override.yml) in the same directory is automatically
merged. Pass multiple file paths explicitly to audit a custom file stack.

Prevents "bind: address already in use" (EADDRINUSE) failures and detects silent wildcard
(0.0.0.0) exposures before running docker compose up.

Exit Codes:
  0: All clear (no collisions detected)
  1: File or syntax error
  2: Port collision detected (address already in use)`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if preflightInstallHook && preflightUninstallHook {
			return fmt.Errorf("--install-hook and --uninstall-hook are mutually exclusive")
		}

		if preflightInstallHook {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			hookPath, err := preflight.InstallHook(dir)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed pre-commit hook: %s\n", hookPath)
			return nil
		}

		if preflightUninstallHook {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			msg, err := preflight.UninstallHook(dir)
			if err != nil {
				return err
			}
			if strings.Contains(strings.ToLower(msg), "not installed") {
				fmt.Fprintln(cmd.OutOrStdout(), msg)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Uninstalled pre-commit hook: %s\n", msg)
			}
			return nil
		}

		var report *preflight.Report
		var err error

		switch len(args) {
		case 0:
			// Auto-discover in current directory
			filePath := ""
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
			report, err = preflightChecker.CheckFile(cmd.Context(), filePath)
		case 1:
			report, err = preflightChecker.CheckFile(cmd.Context(), args[0])
		default:
			report, err = preflightChecker.CheckFiles(cmd.Context(), args...)
		}
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
	multiFile := len(r.Files) > 1
	headerTarget := r.FilePath
	if multiFile {
		headerTarget = strings.Join(r.Files, ", ")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Lantern Preflight: %s\n", headerTarget)
	fmt.Fprintf(cmd.OutOrStdout(), "Analyzed %d declared port mapping(s).\n\n", r.TotalPorts)

	if len(r.Collisions) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "[COLLISION DETECTED] %d port conflict(s) will block startup:\n", len(r.Collisions))
		for _, c := range r.Collisions {
			loc := fmt.Sprintf("line %d", c.Line)
			if multiFile && c.File != "" {
				loc = fmt.Sprintf("%s:%d", filepath.Base(c.File), c.Line)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  - Port %d (%s, %s):\n", c.Port, c.Service, loc)
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
			loc := fmt.Sprintf("line %d", w.Line)
			if multiFile && w.File != "" {
				loc = fmt.Sprintf("%s:%d", filepath.Base(w.File), w.Line)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s (%s): %s -> recommend %s\n", w.Service, loc, w.Original, w.SuggestedFix)
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
	preflightCmd.Flags().BoolVar(&preflightInstallHook, "install-hook", false, "Install a Git pre-commit hook that runs lantern preflight")
	preflightCmd.Flags().BoolVar(&preflightUninstallHook, "uninstall-hook", false, "Uninstall the lantern preflight Git pre-commit hook")
}
