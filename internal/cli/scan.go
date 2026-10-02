package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"lantern/internal/collector"
	"lantern/internal/docker"
	"lantern/internal/network"
	"lantern/internal/process"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Discover TCP listening services",
	RunE: func(cmd *cobra.Command, args []string) error {
		col := collector.NewDefaultCollector()
		listeners, err := col.CollectListeners(cmd.Context())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", err)
			return nil
		}

		if len(listeners) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No active TCP listening sockets detected.")
			return nil
		}

		inspector := process.NewDefaultInspector()
		for i := range listeners {
			if listeners[i].PID > 0 {
				if proc, err := inspector.Inspect(cmd.Context(), listeners[i].PID); err == nil && proc != nil && proc.Name != "" {
					listeners[i].ProcessName = proc.Name
				}
			}
		}

		// Docker correlation (optional enrichment)
		dockerCorrelator := docker.NewDefaultCorrelator()
		containerNames := make([]string, len(listeners))
		for i, l := range listeners {
			if container, _, err := dockerCorrelator.CorrelateListener(cmd.Context(), l); err == nil && container != nil && container.Name != "" {
				containerNames[i] = container.Name
			} else {
				containerNames[i] = "-"
			}
		}

		// Network interface discovery (optional enrichment)
		netClassifier := network.NewDefaultClassifier()
		if ifaces, err := netClassifier.DiscoverInterfaces(cmd.Context()); err == nil {
			_ = ifaces // Discovered interfaces available for exposure enrichment
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 8, 4, ' ', 0)
		fmt.Fprintln(w, "PORT\tADDRESS\tPROCESS\tCONTAINER")
		for i, l := range listeners {
			proc := l.ProcessName
			if proc == "" {
				proc = "unknown"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", l.Port, l.Address, proc, containerNames[i])
		}
		return w.Flush()
	},
}
