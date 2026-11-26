package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/collector"
	"github.com/DhyaanKanoja11/Lantern/internal/docker"
	"github.com/spf13/cobra"
)

// DoctorCheck represents the outcome of a readiness check.
type DoctorCheck struct {
	Name    string
	Status  string // "OK", "WARN", "FAIL"
	Message string
}

type doctorDeps struct {
	goos              string
	geteuid           func() int
	getenv            func(string) string
	lookPath          func(string) (string, error)
	stat              func(string) (os.FileInfo, error)
	isDockerAvailable func(context.Context) bool
	interfaces        func() ([]net.Interface, error)
	checkListeners    func(context.Context) error
}

func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		goos:     runtime.GOOS,
		geteuid:  os.Geteuid,
		getenv:   os.Getenv,
		lookPath: exec.LookPath,
		stat:     os.Stat,
		isDockerAvailable: func(ctx context.Context) bool {
			return docker.NewDefaultCorrelator().IsAvailable(ctx)
		},
		interfaces: net.Interfaces,
		checkListeners: func(ctx context.Context) error {
			_, err := collector.NewDefaultCollector().CollectListeners(ctx)
			return err
		},
	}
}

// RunDoctorChecks performs environment readiness diagnostics.
func RunDoctorChecks(ctx context.Context) []DoctorCheck {
	return runDoctorChecksWithDeps(ctx, defaultDoctorDeps())
}

func runDoctorChecksWithDeps(ctx context.Context, deps doctorDeps) []DoctorCheck {
	var checks []DoctorCheck

	// 1. Operating System
	switch deps.goos {
	case "linux", "darwin", "windows":
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "OK",
			Message: fmt.Sprintf("%s detected (native socket and process inspection supported)", deps.goos),
		})
	default:
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "WARN",
			Message: fmt.Sprintf("%s detected (live socket inspection requires Linux, macOS, or Windows)", deps.goos),
		})
	}

	// 2. Process Privilege Level (Linux)
	if deps.goos == "linux" {
		if deps.geteuid() != 0 {
			checks = append(checks, DoctorCheck{
				Name:    "Process Privilege Level",
				Status:  "WARN",
				Message: "Running as unprivileged user (UID > 0); root-owned listeners (e.g. docker-proxy) will use Docker port metadata inference. Run with sudo for direct process attribution.",
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Process Privilege Level",
				Status:  "OK",
				Message: "Running as root (UID 0, full process and socket inspection enabled)",
			})
		}
	}

	// 3. Socket Inspection Tool
	switch deps.goos {
	case "linux":
		if p, err := deps.lookPath("ss"); err == nil {
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
	case "darwin":
		if p, err := deps.lookPath("lsof"); err == nil {
			checks = append(checks, DoctorCheck{
				Name:    "Socket Inspection Tool (lsof)",
				Status:  "OK",
				Message: fmt.Sprintf("Found at %s", p),
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Socket Inspection Tool (lsof)",
				Status:  "FAIL",
				Message: "'lsof' not found in PATH (macOS socket inspection unavailable)",
			})
		}
	case "windows":
		if p, err := deps.lookPath("netstat"); err == nil {
			checks = append(checks, DoctorCheck{
				Name:    "Socket Inspection Tool (netstat)",
				Status:  "OK",
				Message: fmt.Sprintf("Found at %s", p),
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Socket Inspection Tool (netstat)",
				Status:  "FAIL",
				Message: "'netstat' not found in PATH (Windows socket inspection unavailable)",
			})
		}
	}

	// 4. Process Discovery Mechanism
	switch deps.goos {
	case "linux":
		if fi, err := deps.stat("/proc"); err == nil && fi.IsDir() {
			checks = append(checks, DoctorCheck{
				Name:    "Process Filesystem (/proc)",
				Status:  "OK",
				Message: "Accessible for process attribution",
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Process Filesystem (/proc)",
				Status:  "FAIL",
				Message: "/proc is not accessible (process attribution unavailable)",
			})
		}
	case "windows":
		if p, err := deps.lookPath("tasklist"); err == nil {
			checks = append(checks, DoctorCheck{
				Name:    "Process Inspection Tool (tasklist)",
				Status:  "OK",
				Message: fmt.Sprintf("Found at %s", p),
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Process Inspection Tool (tasklist)",
				Status:  "FAIL",
				Message: "'tasklist' not found in PATH",
			})
		}
	case "darwin":
		if p, err := deps.lookPath("ps"); err == nil {
			checks = append(checks, DoctorCheck{
				Name:    "Process Inspection Tool (ps)",
				Status:  "OK",
				Message: fmt.Sprintf("Found at %s", p),
			})
		} else {
			checks = append(checks, DoctorCheck{
				Name:    "Process Inspection Tool (ps)",
				Status:  "FAIL",
				Message: "'ps' not found in PATH",
			})
		}
	}

	// 5. Container Engine (Docker or Podman)
	checks = append(checks, checkContainerRuntime(ctx, deps))

	// 6. Network Interface Enumeration
	if ifaces, err := deps.interfaces(); err == nil && len(ifaces) > 0 {
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

	// 7. Listener Collection Functional Check
	if err := deps.checkListeners(ctx); err == nil {
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

func checkContainerRuntime(ctx context.Context, deps doctorDeps) DoctorCheck {
	if dockerPath, err := deps.lookPath("docker"); err == nil {
		if deps.isDockerAvailable(ctx) {
			return DoctorCheck{
				Name:    "Docker Environment",
				Status:  "OK",
				Message: fmt.Sprintf("Docker CLI (%s) and daemon reachable", dockerPath),
			}
		}
		return DoctorCheck{
			Name:    "Docker Environment",
			Status:  "WARN",
			Message: fmt.Sprintf("Docker CLI found (%s), but daemon is not accessible", dockerPath),
		}
	}

	if podmanPath, err := deps.lookPath("podman"); err == nil {
		candidates := podmanSocketCandidates(deps)
		for _, sockPath := range candidates {
			if fi, statErr := deps.stat(sockPath); statErr == nil && !fi.IsDir() {
				return DoctorCheck{
					Name:    "Container Engine (Podman)",
					Status:  "OK",
					Message: fmt.Sprintf("Podman CLI (%s) and socket (%s) detected (drop-in container engine)", podmanPath, sockPath),
				}
			}
		}
		if len(candidates) > 0 {
			return DoctorCheck{
				Name:    "Container Engine (Podman)",
				Status:  "WARN",
				Message: fmt.Sprintf("Podman CLI found (%s), but no Podman socket was detected (checked %s)", podmanPath, strings.Join(candidates, ", ")),
			}
		}
		return DoctorCheck{
			Name:    "Container Engine (Podman)",
			Status:  "WARN",
			Message: fmt.Sprintf("Podman CLI found (%s), but no Podman socket was detected", podmanPath),
		}
	}

	return DoctorCheck{
		Name:    "Container Runtime",
		Status:  "WARN",
		Message: "Docker or Podman CLI not found in PATH (container correlation will be skipped)",
	}
}

func podmanSocketCandidates(deps doctorDeps) []string {
	var raw []string

	if dockerHost := strings.TrimSpace(deps.getenv("DOCKER_HOST")); dockerHost != "" {
		switch {
		case strings.HasPrefix(dockerHost, "unix://"):
			raw = append(raw, strings.TrimPrefix(dockerHost, "unix://"))
		case strings.HasPrefix(dockerHost, "npipe://"):
			pipePath := strings.TrimPrefix(dockerHost, "npipe://")
			pipePath = strings.ReplaceAll(pipePath, "/", "\\")
			raw = append(raw, pipePath)
		}
	}
	if xdgDir := strings.TrimSpace(deps.getenv("XDG_RUNTIME_DIR")); xdgDir != "" {
		raw = append(raw, filepath.Join(xdgDir, "podman", "podman.sock"))
	}

	switch deps.goos {
	case "linux":
		if uid := deps.geteuid(); uid >= 0 {
			raw = append(raw, filepath.Join("/run/user", strconv.Itoa(uid), "podman", "podman.sock"))
		}
		raw = append(raw, "/run/podman/podman.sock")
	case "darwin":
		if home := strings.TrimSpace(deps.getenv("HOME")); home != "" {
			raw = append(raw, filepath.Join(home, ".local", "share", "containers", "podman", "machine", "podman.sock"))
		}
	case "windows":
		raw = append(raw, `\\.\pipe\podman-machine-default`, `\\.\pipe\podman-machine-default-root`)
		if userProfile := strings.TrimSpace(deps.getenv("USERPROFILE")); userProfile != "" {
			raw = append(raw, filepath.Join(userProfile, ".local", "share", "containers", "podman", "machine", "podman.sock"))
		}
	}

	seen := make(map[string]bool, len(raw))
	var unique []string
	for _, p := range raw {
		clean := p
		if !strings.HasPrefix(p, `\\.\pipe\`) {
			clean = filepath.Clean(p)
		}
		if !seen[clean] {
			seen[clean] = true
			unique = append(unique, clean)
		}
	}
	return unique
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
