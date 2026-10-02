package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var whyCmd = &cobra.Command{
	Use:   "why <port>",
	Short: "Explain why a network service is reachable",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid port number: %s", args[0])
		}
		fmt.Printf("Analyzing exposure path for port %d...\n", port)
		fmt.Println("(why placeholder: exposure analysis engine will be active in Milestone 7)")
		return nil
	},
}
