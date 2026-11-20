package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"lantern/internal/domain"
	"lantern/internal/explain"
)

// TextFormatter renders human-readable plain text output for the CLI.
type TextFormatter struct{}

// NewTextFormatter creates a new instance of TextFormatter.
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{}
}

// RenderScan renders the table of discovered listening services for `lantern scan`.
// Optional diagnostic notices (e.g. Docker daemon warnings) are rendered beneath the table.
func (t *TextFormatter) RenderScan(w io.Writer, list []domain.ExposureSummary, notices ...string) error {
	if len(list) == 0 {
		fmt.Fprintln(w, "No active TCP listening sockets detected.")
		for _, n := range notices {
			fmt.Fprintf(w, "\nNote: %s\n", n)
		}
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 8, 4, ' ', 0)
	fmt.Fprintln(tw, "PORT\tADDRESS\tPROCESS\tCONTAINER\tREACHABILITY")
	for _, s := range list {
		cName := s.ContainerName
		if cName == "" {
			cName = "-"
		}
		proc := s.ProcessName
		if proc == "" {
			proc = "unknown"
		}
		reach := s.Reachability
		if reach == "" {
			reach = "unknown"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", s.Port, s.Address, proc, cName, reach)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(notices) > 0 {
		fmt.Fprintln(w)
		for _, n := range notices {
			fmt.Fprintf(w, "Note: %s\n", n)
		}
		fmt.Fprintln(w, "Run 'lantern doctor' for complete environment diagnostics.")
	}
	return nil
}

// RenderWhy renders the structured exposure explanation for `lantern why <port>`.
func (t *TextFormatter) RenderWhy(w io.Writer, exp *domain.Exposure) error {
	if exp == nil {
		return fmt.Errorf("cannot render nil exposure")
	}

	expl := explain.Explain(exp)
	if expl == nil {
		return fmt.Errorf("failed to generate explanation")
	}

	// 1. Header: Service and Port
	serviceName := "Service"
	if exp.Container != nil && exp.Container.Name != "" {
		serviceName = exp.Container.Name
	} else if exp.Process != nil && exp.Process.Name != "" {
		serviceName = exp.Process.Name
	} else if exp.Listener.ProcessName != "" {
		serviceName = exp.Listener.ProcessName
	}
	fmt.Fprintf(w, "%s :%d\n\n", serviceName, exp.Port)

	// Attribution Notice for Inferred Container Attribution
	if exp.Container != nil && exp.Container.AttributionMode == domain.AttributionInferred {
		fmt.Fprintf(w, "ATTRIBUTION NOTICE\n\n")
		fmt.Fprintf(w, "Attribution mode: INFERRED (uncertain)\n")
		if exp.Listener.PID == 0 {
			fmt.Fprintf(w, "  - Process verification: Unverified (host socket PID was not readable via /proc, typical for unprivileged users with root-owned docker-proxy).\n")
		} else {
			fmt.Fprintf(w, "  - Process verification: Unverified (PID %d process inspection could not directly verify container ownership).\n", exp.Listener.PID)
		}
		cName := exp.Container.Name
		if cName == "" {
			cName = exp.Container.ID
		}
		if exp.DockerMapping != nil {
			fmt.Fprintf(w, "  - Evidence used: Docker daemon reports container %q published host port %d (%s:%d -> %d/%s).\n",
				cName, exp.Port, exp.DockerMapping.HostIP, exp.DockerMapping.HostPort, exp.DockerMapping.ContainerPort, exp.DockerMapping.Protocol)
		} else {
			fmt.Fprintf(w, "  - Evidence used: Docker daemon reports container %q published host port %d.\n", cName, exp.Port)
		}
		fmt.Fprintf(w, "  - Live remediation: BLOCKED. Automated modification via 'lantern fix' is disabled for inferred attribution to prevent modifying files on unverified evidence.\n")
		fmt.Fprintf(w, "  - Next steps: Run with elevated privileges (sudo) to verify process ownership, or use 'lantern fix %d --dry-run' to inspect the proposed change safely.\n\n", exp.Port)
	}

	// 2. EXPOSURE PATH
	fmt.Fprintf(w, "EXPOSURE PATH\n\n")
	pathTree := explain.FormatPath(exp, expl.RootCause)
	if pathTree != "" {
		fmt.Fprintln(w, pathTree)
	} else {
		fmt.Fprintln(w, "No exposure path available")
	}
	fmt.Fprintln(w)

	// 3. ROOT CAUSE / LIKELY SOURCE
	rcTitle := "ROOT CAUSE"
	if !expl.RootCause.Certain {
		rcTitle = "LIKELY SOURCE"
	}
	fmt.Fprintf(w, "%s\n\n", rcTitle)
	if expl.RootCause.Source != "" && expl.RootCause.Source != "unknown" {
		fmt.Fprintf(w, "%s\n", expl.RootCause.Source)
		if expl.RootCause.Detail != "" && expl.RootCause.Detail != expl.RootCause.Source {
			fmt.Fprintf(w, "\n    %s\n", expl.RootCause.Detail)
		}
	} else {
		fmt.Fprintf(w, "%s\n", expl.RootCause.Description)
	}
	fmt.Fprintln(w)

	// 4. REACHABILITY
	fmt.Fprintf(w, "REACHABILITY\n\n")
	localStr := "NO"
	if exp.Reachability.Local {
		localStr = "YES"
	}
	lanStr := "NO"
	if strings.EqualFold(exp.Reachability.LAN, "yes") {
		lanStr = "YES"
	} else if strings.EqualFold(exp.Reachability.LAN, "possible") {
		lanStr = "POSSIBLE"
	}
	internetStr := "UNKNOWN"
	if exp.Reachability.Internet != "" {
		internetStr = strings.ToUpper(exp.Reachability.Internet)
	}
	fmt.Fprintf(w, "Local machine: %s\n", localStr)
	fmt.Fprintf(w, "LAN:           %s\n", lanStr)
	fmt.Fprintf(w, "Internet:      %s\n", internetStr)

	// 5. RECOMMENDED CHANGE (only if recommendation exists)
	if exp.Recommendation != nil && exp.Recommendation.Suggested != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "RECOMMENDED CHANGE\n\n")
		fmt.Fprintf(w, "    %s\n", exp.Recommendation.Suggested)
		if exp.Recommendation.Description != "" {
			fmt.Fprintf(w, "\n%s\n", exp.Recommendation.Description)
		}
	}

	return nil
}
