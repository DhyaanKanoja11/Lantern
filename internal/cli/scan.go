package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Discover TCP listening services",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("PORT     ADDRESS       PROCESS        CONTAINER")
		fmt.Println("(scan placeholder: listening service detection will be active in Milestone 2)")
	},
}
