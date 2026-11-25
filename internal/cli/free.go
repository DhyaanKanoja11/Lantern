package cli

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/reclaim"
	"github.com/spf13/cobra"
)

var (
	freeForceFlag   bool
	freeYesFlag     bool
	freeDryRunFlag  bool
	freeTimeoutFlag time.Duration

	freeAnalyzer  exposure.Analyzer = exposure.NewDefaultAnalyzer()
	freeReclaimer reclaim.Reclaimer = reclaim.NewDefaultReclaimer()
)

var freeCmd = &cobra.Command{
	Use:     "free <port>",
	Aliases: []string{"kill"},
	Short:   "Free an occupied network port by safely stopping its container or terminating its process",
	Long: `Lantern Free inspects what is occupying a network port and safely frees it.

Unlike blunt utilities (e.g. kill -9 or kill-port) that blindly terminate
docker-proxy and corrupt Docker networking state, Lantern is context-aware:
- If the port is published by a Docker container, it stops the container cleanly.
- If the port is bound by a native process, it terminates the process.

Prompts for confirmation before taking action unless --yes or --force is provided.

--yes skips the prompt but still shuts things down gracefully: processes get
SIGTERM and are only killed if they're still around after --timeout.
--force skips the prompt and kills the process immediately (SIGKILL), with no
chance to flush data. Avoid it for databases.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		portVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port number %q: must be an integer between 1 and 65535", args[0])
		}
		if portVal == 0 || portVal > 65535 {
			return fmt.Errorf("invalid port number %d: port must be between 1 and 65535", portVal)
		}

		port := uint16(portVal)
		analyzer := freeAnalyzer
		exp, err := analyzer.Why(cmd.Context(), port, ".")
		if err != nil {
			if errors.Is(err, exposure.ErrNoListener) {
				fmt.Fprintf(cmd.OutOrStdout(), "Port %d is already free (no listening service found).\n", port)
				return nil
			}
			return err
		}

		reclaimer := freeReclaimer
		plan, err := reclaimer.Plan(cmd.Context(), exp)
		if err != nil {
			return err
		}

		if plan.TargetType == reclaim.TargetUnknown {
			fmt.Fprintf(cmd.OutOrStdout(), "Port %d is currently occupied, but the listener process/container is unknown.\n", port)
			fmt.Fprintln(cmd.OutOrStdout(), "(Socket inspection may require running with elevated privileges or sudo.)")
			return fmt.Errorf("cannot free port %d: unprivileged or unknown listener", port)
		}

		// Dry-run preview
		if freeDryRunFlag {
			fmt.Fprintf(cmd.OutOrStdout(), "[DRY RUN] Previewing action to free port %d:\n", port)
			if plan.TargetType == reclaim.TargetContainer {
				fmt.Fprintln(cmd.OutOrStdout(), "  Target:  Docker container")
				fmt.Fprintf(cmd.OutOrStdout(), "  Name:    %s\n", plan.ContainerName)
				if plan.ContainerID != "" {
					shortID := plan.ContainerID
					if len(shortID) > 12 {
						shortID = shortID[:12]
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  ID:      %s\n", shortID)
				}
				if plan.Image != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Image:   %s\n", plan.Image)
				}
				if plan.Project != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Project: %s (service: %s)\n", plan.Project, plan.Service)
				}
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "  Target:  Native process")
				fmt.Fprintf(cmd.OutOrStdout(), "  PID:     %d\n", plan.PID)
				if plan.ProcessName != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Name:    %s\n", plan.ProcessName)
				}
				if plan.CommandLine != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Command: %s\n", plan.CommandLine)
				}
				if plan.User != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  User:    %s\n", plan.User)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "No changes made (dry-run mode).")
			return nil
		}

		// Interactive Confirmation Prompt
		skipPrompt := freeForceFlag || freeYesFlag
		if !skipPrompt {
			if plan.TargetType == reclaim.TargetContainer {
				fmt.Fprintf(cmd.OutOrStdout(), "Port %d is currently occupied by Docker container:\n", port)
				fmt.Fprintf(cmd.OutOrStdout(), "  Container: %s\n", plan.ContainerName)
				if plan.ContainerID != "" {
					shortID := plan.ContainerID
					if len(shortID) > 12 {
						shortID = shortID[:12]
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  ID:        %s\n", shortID)
				}
				if plan.Image != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Image:     %s\n", plan.Image)
				}
				if plan.Project != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Project:   %s (service: %s)\n", plan.Project, plan.Service)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprint(cmd.OutOrStdout(), "Stop this container? [y/N]: ")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Port %d is currently occupied by native process:\n", port)
				fmt.Fprintf(cmd.OutOrStdout(), "  Process: %s\n", plan.ProcessName)
				fmt.Fprintf(cmd.OutOrStdout(), "  PID:     %d\n", plan.PID)
				if plan.CommandLine != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  Command: %s\n", plan.CommandLine)
				}
				if plan.User != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  User:    %s\n", plan.User)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprint(cmd.OutOrStdout(), "Terminate this process? [y/N]: ")
			}

			reader := bufio.NewReader(cmd.InOrStdin())
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}

			answer := strings.ToLower(strings.TrimSpace(input))
			if answer != "y" && answer != "yes" {
				fmt.Fprintf(cmd.OutOrStdout(), "[ABORTED] Port %d was not freed.\n", port)
				return nil
			}
		}

		// Apply Reclaim
		timeout := freeTimeoutFlag
		if timeout <= 0 {
			timeout = 10 * time.Second
		}

		// Only --force skips the graceful shutdown. --yes just means "don't ask".
		res, err := reclaimer.Apply(cmd.Context(), plan, freeForceFlag, timeout)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "[OK] %s. Port %d is now free.\n", res.Description, port)
		return nil
	},
}

func init() {
	freeCmd.Flags().BoolVarP(&freeForceFlag, "force", "f", false, "Skip the confirmation prompt and kill immediately (SIGKILL) instead of shutting down gracefully")
	freeCmd.Flags().BoolVarP(&freeYesFlag, "yes", "y", false, "Skip the confirmation prompt; still shuts down gracefully")
	freeCmd.Flags().BoolVar(&freeDryRunFlag, "dry-run", false, "Preview which container or process would be stopped without taking action")
	freeCmd.Flags().DurationVar(&freeTimeoutFlag, "timeout", 10*time.Second, "Timeout for stopping container or terminating process")
}
