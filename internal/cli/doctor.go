package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system prerequisites and permissions",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Lantern Doctor")
		fmt.Println()
		fmt.Println("Scaffold initialized. System detection will be active in Milestone 2.")
	},
}
