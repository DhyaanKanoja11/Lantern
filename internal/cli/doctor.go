package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
	"lantern/internal/collector"
	"lantern/internal/docker"
)

// DoctorCheck represents the outcome of a readiness check.
type DoctorCheck struct {
	Name    string
	Status  string // "OK", "WARN", "FAIL"
	Message string
}

// RunDoctorChecks performs environment readiness diagnostics.
func RunDoctorChecks(ctx context.Context) []DoctorCheck {
	var checks []DoctorCheck

	// 1. Operating System
	if runtime.GOOS == "linux" {
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "OK",
			Message: "Linux detected (socket and process inspection supported)",
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "WARN",
			Message: fmt.Sprintf("%s detected (live socket inspection requires Linux or WSL2)", runtime.GOOS),
		})
	}

	// 2. Command 'ss'
	if p, err := exec.LookPath("ss"); err == nil {
		checks = append(checks, DoctorCheck{
			Name:    "Socket Inspection Tool (ss)",
			Status:  "OK",
			Message: fmt.Sprintf("Found at %s", p),
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:    "Socket Inspection Tool (ss)",
			Status:  "WARN",
			Message: "'ss' not found in PATH (will fall back to /proc/net/tcp)",
		})
	}

	// 3. /proc Filesystem Accessibility
	if fi, err := os.Stat("/proc"); err == nil && fi.IsDir() {
		checks = append(checks, DoctorCheck{
			Name:    "Process Filesystem (/proc)",
			Status:  "OK",
			Message: "Accessible for process attribution",
		})
	} else {
		if runtime.GOOS == "linux" {
			checks = append(checks, DoctorCheck{
				Name:    "Process Filesystem (/proc)",
				Status:  "FAIL",
				Message: "/proc is not accessible (process attribution unavailable)",
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Process Filesystem (/proc)",
				Status:  "WARN",
				Message: "/proc not present on non-Linux OS",
			})
		}
	}

	// 4. Docker CLI and Daemon
	if dockerPath, err := exec.LookPath("docker"); err == nil {
		correlator := docker.NewDefaultCorrelator()
		if correlator.IsAvailable(ctx) {
			checks = append(checks, DoctorCheck{
				Name:    "Docker Environment",
				Status:  "OK",
				Message: fmt.Sprintf("Docker CLI (%s) and daemon reachable", dockerPath),
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Docker Environment",
				Status:  "WARN",
				Message: fmt.Sprintf("Docker CLI found (%s), but daemon is not accessible", dockerPath),
			})
		}
	} else {
		checks = append(checks, DoctorCheck{
			Name:    "Docker Environment",
			Status:  "WARN",
			Message: "Docker CLI not found in PATH (container correlation will be skipped)",
		})
	}

	// 5. Network Interface Enumeration
	if ifaces, err := net.Interfaces(); err == nil && len(ifaces) > 0 {
		checks = append(checks, DoctorCheck{
			Name:    "Network Interfaces",
			Status:  "OK",
			Message: fmt.Sprintf("%d local network interface(s) detected", len(ifaces)),
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:    "Network Interfaces",
			Status:  "FAIL",
			Message: "Failed to enumerate local network interfaces",
		})
	}

	// 6. Listener Collection Functional Check
	col := collector.NewDefaultCollector()
	if _, err := col.CollectListeners(ctx); err == nil {
		checks = append(checks, DoctorCheck{
			Name:    "Listener Collector",
			Status:  "OK",
			Message: "Listener collection functional",
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:    "Listener Collector",
			Status:  "WARN",
			Message: fmt.Sprintf("Listener collection check: %v", err),
		})
	}

	return checks
}

// RenderDoctor prints the doctor checks in a clean tabular format.
func RenderDoctor(w io.Writer, checks []DoctorCheck) {
	fmt.Fprintln(w, "Lantern Doctor - Environment Diagnostics")
	fmt.Fprintln(w)
	for _, c := range checks {
		symbol := "[OK]  "
		if c.Status == "WARN" {
			symbol = "[WARN]"
		} else if c.Status == "FAIL" {
			symbol = "[FAIL]"
		}
		fmt.Fprintf(w, " %s %s: %s\n", symbol, c.Name, c.Message)
	}
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system prerequisites and permissions",
	Run: func(cmd *cobra.Command, args []string) {
		checks := RunDoctorChecks(cmd.Context())
		RenderDoctor(cmd.OutOrStdout(), checks)
	},
}
