package cli

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"lantern/internal/exposure"
	"lantern/internal/output"
)

var whyCmd = &cobra.Command{
	Use:   "why <port>",
	Short: "Explain why a network service is reachable",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		portVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port number %q: must be an integer between 1 and 65535", args[0])
		}
		if portVal == 0 || portVal > 65535 {
			return fmt.Errorf("invalid port number %d: port must be between 1 and 65535", portVal)
		}

		analyzer := exposure.NewDefaultAnalyzer()
		exp, err := analyzer.Why(cmd.Context(), uint16(portVal), ".")
		if err != nil {
			if errors.Is(err, exposure.ErrNoListener) {
				fmt.Fprintf(cmd.OutOrStdout(), "No listening service found on port %d.\n", portVal)
				return nil
			}
			return err
		}

		formatter := output.NewTextFormatter()
		return formatter.RenderWhy(cmd.OutOrStdout(), exp)
	},
}
