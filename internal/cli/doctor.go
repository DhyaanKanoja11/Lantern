package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

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

// RunDoctorChecks performs environment readiness diagnostics.
func RunDoctorChecks(ctx context.Context) []DoctorCheck {
	var checks []DoctorCheck

	// 1. Operating System
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "OK",
			Message: fmt.Sprintf("%s detected (native socket and process inspection supported)", runtime.GOOS),
		})
	default:
		checks = append(checks, DoctorCheck{
			Name:    "Operating System",
			Status:  "WARN",
			Message: fmt.Sprintf("%s detected (live socket inspection requires Linux, macOS, or Windows)", runtime.GOOS),
		})
	}

	// 2. Process Privilege Level (Linux)
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
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
	switch runtime.GOOS {
	case "linux":
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
	case "darwin":
		if p, err := exec.LookPath("lsof"); err == nil {
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
		if p, err := exec.LookPath("netstat"); err == nil {
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
	switch runtime.GOOS {
	case "linux":
		if fi, err := os.Stat("/proc"); err == nil && fi.IsDir() {
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
		if p, err := exec.LookPath("tasklist"); err == nil {
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
		if p, err := exec.LookPath("ps"); err == nil {
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

	// 5. Container Engine (Docker / Podman)
	checks = append(checks, checkContainerRuntime(ctx, defaultDoctorDeps()))

	// 6. Network Interface Enumeration
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

	// 7. Listener Collection Functional Check
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

type doctorDeps struct {
	lookPath      func(string) (string, error)
	isDockerAvail func(context.Context) bool
	probePodman   func(context.Context, string) bool
	statPath      func(string) (os.FileInfo, error)
	getenv        func(string) string
	getuid        func() int
	userHomeDir   func() (string, error)
	goos          string
}

func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		lookPath: exec.LookPath,
		isDockerAvail: func(ctx context.Context) bool {
			return docker.NewDefaultCorrelator().IsAvailable(ctx)
		},
		probePodman: defaultPodmanProbe,
		statPath:    os.Stat,
		getenv:      os.Getenv,
		getuid:      os.Getuid,
		userHomeDir: os.UserHomeDir,
		goos:        runtime.GOOS,
	}
}

func defaultPodmanProbe(ctx context.Context, podmanPath string) bool {
	probeCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		probeCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(probeCtx, podmanPath, "ps", "-q")
	return cmd.Run() == nil
}

func checkContainerRuntime(ctx context.Context, deps doctorDeps) DoctorCheck {
	if deps.lookPath != nil {
		if dockerPath, err := deps.lookPath("docker"); err == nil {
			if deps.isDockerAvail != nil && deps.isDockerAvail(ctx) {
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
			sockPath, sockFound := findPodmanSocket(deps)
			engineReachable := deps.probePodman != nil && deps.probePodman(ctx, podmanPath)

			switch {
			case sockFound && engineReachable:
				return DoctorCheck{
					Name:    "Container Environment",
					Status:  "OK",
					Message: fmt.Sprintf("Podman container engine detected (%s, socket: %s)", podmanPath, sockPath),
				}
			case !sockFound && engineReachable:
				msg := fmt.Sprintf("Podman container engine detected (%s) and CLI reachable (no Podman socket found)", podmanPath)
				if deps.goos == "windows" {
					msg = fmt.Sprintf("Podman container engine detected (%s) and CLI reachable", podmanPath)
				}
				return DoctorCheck{
					Name:    "Container Environment",
					Status:  "OK",
					Message: msg,
				}
			case sockFound && !engineReachable:
				return DoctorCheck{
					Name:    "Container Environment",
					Status:  "WARN",
					Message: fmt.Sprintf("Podman CLI found (%s) and socket exists (%s), but engine is not accessible", podmanPath, sockPath),
				}
			default:
				return DoctorCheck{
					Name:    "Container Environment",
					Status:  "WARN",
					Message: fmt.Sprintf("Podman CLI found (%s), but no Podman socket found and engine is not accessible", podmanPath),
				}
			}
		}
	}

	return DoctorCheck{
		Name:    "Container Environment",
		Status:  "WARN",
		Message: "Neither Docker nor Podman CLI found in PATH (container correlation will be skipped)",
	}
}

func parseUnixSocketHost(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	if strings.HasPrefix(val, "unix:///") {
		return strings.TrimPrefix(val, "unix://")
	}
	if strings.HasPrefix(val, "/") {
		return val
	}
	return ""
}

func podmanSocketCandidates(deps doctorDeps) []string {
	var candidates []string

	if deps.getenv != nil {
		if ch := parseUnixSocketHost(deps.getenv("CONTAINER_HOST")); ch != "" {
			candidates = append(candidates, ch)
		}
		if dh := parseUnixSocketHost(deps.getenv("DOCKER_HOST")); dh != "" {
			candidates = append(candidates, dh)
		}
	}

	switch deps.goos {
	case "linux":
		if deps.getenv != nil {
			if xdg := strings.TrimSpace(deps.getenv("XDG_RUNTIME_DIR")); path.IsAbs(xdg) {
				candidates = append(candidates, path.Join(xdg, "podman", "podman.sock"))
			}
		}
		if deps.getuid != nil {
			if uid := deps.getuid(); uid >= 0 {
				candidates = append(candidates, fmt.Sprintf("/run/user/%d/podman/podman.sock", uid))
				if uid == 0 && deps.getenv != nil {
					if sudoUID := strings.TrimSpace(deps.getenv("SUDO_UID")); sudoUID != "" {
						if parsed, err := strconv.Atoi(sudoUID); err == nil && parsed > 0 {
							candidates = append(candidates, fmt.Sprintf("/run/user/%d/podman/podman.sock", parsed))
						}
					}
				}
			}
		}
		candidates = append(candidates,
			"/run/podman/podman.sock",
			"/var/run/podman/podman.sock",
		)
	case "darwin":
		if deps.getenv != nil {
			if xdg := strings.TrimSpace(deps.getenv("XDG_RUNTIME_DIR")); path.IsAbs(xdg) {
				candidates = append(candidates,
					path.Join(xdg, "podman", "podman-machine-default-api.sock"),
					path.Join(xdg, "podman", "podman.sock"),
				)
			}
			if tmpdir := strings.TrimSpace(deps.getenv("TMPDIR")); path.IsAbs(tmpdir) {
				candidates = append(candidates, path.Join(tmpdir, "podman", "podman-machine-default-api.sock"))
			}
		}
		if deps.userHomeDir != nil {
			if home, err := deps.userHomeDir(); err == nil {
				home = strings.TrimSpace(home)
				if path.IsAbs(home) {
					base := path.Join(home, ".local", "share", "containers", "podman", "machine")
					candidates = append(candidates,
						path.Join(base, "podman.sock"),
						path.Join(base, "applehv", "podman.sock"),
						path.Join(base, "qemu", "podman.sock"),
						path.Join(base, "libkrun", "podman.sock"),
					)
				}
			}
		}
		candidates = append(candidates, "/var/run/podman/podman.sock")
	}

	seen := make(map[string]bool, len(candidates))
	deduped := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		deduped = append(deduped, c)
	}
	return deduped
}

func findPodmanSocket(deps doctorDeps) (string, bool) {
	if deps.statPath == nil {
		return "", false
	}
	for _, candidate := range podmanSocketCandidates(deps) {
		if isUnixSocket(deps.statPath, candidate) {
			return candidate, true
		}
	}
	return "", false
}

func isUnixSocket(statPath func(string) (os.FileInfo, error), sockPath string) bool {
	fi, err := statPath(sockPath)
	if err != nil || fi == nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
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
