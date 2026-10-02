package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"lantern/internal/collector"
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

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 8, 4, ' ', 0)
		fmt.Fprintln(w, "PORT\tADDRESS\tPROCESS")
		for _, l := range listeners {
			proc := l.ProcessName
			if proc == "" {
				proc = "unknown"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\n", l.Port, l.Address, proc)
		}
		return w.Flush()
	},
}
