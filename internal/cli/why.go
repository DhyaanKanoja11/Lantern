package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/spf13/cobra"
)

var (
	whyFormat string
	whyJSON   bool
)

var whyCmd = &cobra.Command{
	Use:   "why <port>",
	Short: "Explain why a network service is reachable",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("port required. Run 'lantern scan' to see active listening ports, then run 'lantern why <port>'")
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts 1 arg(s), received %d", len(args))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		portVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port number %q: must be an integer between 1 and 65535", args[0])
		}
		if portVal == 0 || portVal > 65535 {
			return fmt.Errorf("invalid port number %d: port must be between 1 and 65535", portVal)
		}

		format := strings.ToLower(whyFormat)
		if whyJSON {
			format = "json"
		}

		var formatter output.Formatter
		switch format {
		case "text", "":
			formatter = output.NewTextFormatter()
		case "json":
			formatter = output.NewJSONFormatter()
		case "sarif":
			formatter = output.NewSarifFormatter(Version)
		default:
			return fmt.Errorf("unsupported output format %q: must be one of text, json, sarif", whyFormat)
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

		return formatter.RenderWhy(cmd.OutOrStdout(), exp)
	},
}

func init() {
	whyCmd.Flags().StringVarP(&whyFormat, "format", "f", "text", "Output format: text, json, sarif")
	whyCmd.Flags().BoolVar(&whyJSON, "json", false, "Output result as JSON (alias for --format json)")
}
