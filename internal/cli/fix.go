package cli

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"lantern/internal/domain"
	"lantern/internal/exposure"
	"lantern/internal/remediation"
)

var (
	dryRunFlag    bool
	fixAnalyzer   exposure.Analyzer      = exposure.NewDefaultAnalyzer()
	fixRemediator remediation.Remediator = remediation.NewDefaultRemediator()
)

var fixCmd = &cobra.Command{
	Use:   "fix <port>",
	Short: "Apply automated remediation to a supported exposure",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		portVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port number %q: must be an integer between 1 and 65535", args[0])
		}
		if portVal == 0 || portVal > 65535 {
			return fmt.Errorf("invalid port number %d: port must be between 1 and 65535", portVal)
		}

		analyzer := fixAnalyzer
		exp, err := analyzer.Why(cmd.Context(), uint16(portVal), ".")
		if err != nil {
			if errors.Is(err, exposure.ErrNoListener) {
				fmt.Fprintf(cmd.OutOrStdout(), "No listening service found on port %d.\n", portVal)
				return nil
			}
			return err
		}

		remediator := fixRemediator
		plan, err := remediator.Plan(cmd.Context(), exp)
		if err != nil {
			return err
		}

		switch plan.Status {
		case domain.RemediationUnsupported:
			fmt.Fprintln(cmd.OutOrStdout(), "Lantern Fix")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.OutOrStdout(), "Port: %d\n", portVal)
			if plan.Before != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Current:\n    %s\n\n", plan.Before)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Automatic remediation is not supported for this exposure type.")
			fmt.Fprintln(cmd.OutOrStdout(), plan.Reason)
			return nil

		case domain.RemediationUnsafe:
			fmt.Fprintln(cmd.OutOrStdout(), "Lantern Fix")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.OutOrStdout(), "Port: %d\n", portVal)
			fmt.Fprintln(cmd.OutOrStdout(), "Remediation cannot be safely applied:")
			fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", plan.Reason)
			return nil

		case domain.RemediationSupported:
			fmt.Fprintln(cmd.OutOrStdout(), "Lantern Fix")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.OutOrStdout(), "Port: %d\n", portVal)
			fmt.Fprintf(cmd.OutOrStdout(), "Root cause: %s:%d\n\n", plan.File, plan.Line)
			fmt.Fprintf(cmd.OutOrStdout(), "Current:\n    %s\n\n", plan.Before)
			fmt.Fprintf(cmd.OutOrStdout(), "Proposed:\n    %s\n\n", plan.After)
			fmt.Fprintf(cmd.OutOrStdout(), "This will modify:\n    %s\n\n", plan.File)

			if dryRunFlag {
				backupPath, _ := remediation.DetermineBackupPath(plan.File)
				fmt.Fprintln(cmd.OutOrStdout(), "Dry-run mode: no changes will be made.")
				if backupPath != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "Backup that would be created: %s\n", backupPath)
				}
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), "A backup will be created before modification.")
			fmt.Fprint(cmd.OutOrStdout(), "\nApply this change? [y/N]: ")

			reader := bufio.NewReader(cmd.InOrStdin())
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(answer)

			if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
				fmt.Fprintln(cmd.OutOrStdout(), "Operation cancelled. No changes made.")
				return nil
			}

			res, err := remediator.Apply(cmd.Context(), plan)
			if err != nil {
				if errors.Is(err, remediation.ErrFileChanged) {
					fmt.Fprintln(cmd.OutOrStdout(), "\nThe configuration file changed after analysis.")
					fmt.Fprintln(cmd.OutOrStdout())
					fmt.Fprintln(cmd.OutOrStdout(), "File:")
					fmt.Fprintf(cmd.OutOrStdout(), "    %s\n\n", plan.File)
					fmt.Fprintln(cmd.OutOrStdout(), "Lantern will not apply the planned change.")
					fmt.Fprintln(cmd.OutOrStdout())
					fmt.Fprintln(cmd.OutOrStdout(), "Please run:")
					fmt.Fprintf(cmd.OutOrStdout(), "    lantern fix %d\n\n", portVal)
					fmt.Fprintln(cmd.OutOrStdout(), "again to analyze the current configuration.")
					return nil
				}
				return fmt.Errorf("error applying fix: %w", err)
			}

			if !res.Success {
				fmt.Fprintf(cmd.OutOrStdout(), "\nChange applied, but verification failed: %s\nThe original file backup is available at: %s\n", res.ErrorMessage, res.BackupPath)
				return fmt.Errorf("remediation verification failed")
			}

			fmt.Fprintln(cmd.OutOrStdout(), "\nFix applied successfully.")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Before:")
			fmt.Fprintf(cmd.OutOrStdout(), "    %s\n\n", res.BeforeState)
			fmt.Fprintln(cmd.OutOrStdout(), "After:")
			fmt.Fprintf(cmd.OutOrStdout(), "    %s\n\n", res.AfterState)
			fmt.Fprintf(cmd.OutOrStdout(), "Backup:\n    %s\n", res.BackupPath)
			return nil

		default:
			return fmt.Errorf("unknown remediation status: %s", plan.Status)
		}
	},
}

func init() {
	fixCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Preview planned remediation without modifying files")
}
