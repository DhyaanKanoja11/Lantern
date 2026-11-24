package cli

import (
	"context"

	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/mcp"
	"github.com/DhyaanKanoja11/Lantern/internal/reclaim"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start Lantern Model Context Protocol (MCP) stdio server for AI agents",
	Long: `Start the Model Context Protocol (MCP) server over standard I/O (stdio).

This allows AI coding agents (such as Claude Code, Claude Desktop, Cursor, and Windsurf)
to natively invoke Lantern tools:
- lantern_scan: Inspect active TCP listening sockets and exposure reachability
- lantern_why: Trace port configuration causality and root cause
- lantern_free: Safely reclaim ports by stopping Docker containers or terminating processes
- lantern_doctor: Check environment readiness and tool availability`,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv := mcp.NewServer(
			Version,
			exposure.NewDefaultAnalyzer(),
			reclaim.NewDefaultReclaimer(),
			func(ctx context.Context) any {
				return RunDoctorChecks(ctx)
			},
		)
		return srv.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
	},
}
