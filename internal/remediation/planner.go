package remediation

import (
	"fmt"
	"os"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/explain"
)

// Plan evaluates an exposure and determines whether a safe, deterministic remediation can be executed.
func Plan(exp *domain.Exposure) *domain.Remediation {
	if exp == nil {
		return &domain.Remediation{
			Status: domain.RemediationUnsafe,
			Reason: "No exposure data provided",
		}
	}

	rc := explain.ClassifyRootCause(exp.Listener, exp.Process, exp.Container, exp.DockerMapping, exp.Config, exp.Reachability)

	// 1. Native process wildcard or specific bind -> Unsupported in M9
	if rc.Type == explain.RootCauseProcessWildcardBind || rc.Type == explain.RootCauseProcessSpecificBind {
		before := fmt.Sprintf("%s:%d", exp.BindAddress, exp.Port)
		after := fmt.Sprintf("127.0.0.1:%d", exp.Port)
		return &domain.Remediation{
			Status: domain.RemediationUnsupported,
			Type:   "bind_localhost",
			Before: before,
			After:  after,
			Reason: "Automatic remediation is not supported for native process configurations. Please configure your application to bind to 127.0.0.1 directly.",
		}
	}

	// 2. Docker published port without Compose file -> Unsupported in M9
	if rc.Type == explain.RootCauseDockerPublishedPort {
		return &domain.Remediation{
			Status: domain.RemediationUnsupported,
			Reason: "Docker port was published without Docker Compose configuration. Automatic remediation is not supported for standalone docker run containers.",
		}
	}

	// 3. Process loopback bind -> Already secure
	if rc.Type == explain.RootCauseProcessLoopbackBind {
		return &domain.Remediation{
			Status: domain.RemediationUnsupported,
			Reason: "Service is already bound strictly to loopback (127.0.0.1).",
		}
	}

	// 4. Insufficient or unresolved evidence -> Unsafe
	if rc.Type == explain.RootCauseUnresolved {
		return &domain.Remediation{
			Status: domain.RemediationUnsafe,
			Reason: "Insufficient evidence to determine root cause with certainty.",
		}
	}

	// 5. Docker Compose published port -> Check validity for automatic remediation
	if rc.Type == explain.RootCauseComposePublishedPort {
		// If the Compose configuration evidence itself is uncertain (e.g. ambiguous matches)
		if exp.Config != nil && !exp.Config.Certain {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: "Root cause configuration is uncertain (LIKELY SOURCE). Automatic remediation requires verified certainty.",
			}
		}

		if exp.Config == nil || exp.Config.File == "" {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: "Compose configuration file path is missing from evidence.",
			}
		}

		cleanHostIP := strings.Trim(strings.TrimSpace(exp.Config.HostIP), "[]")
		if cleanHostIP == "127.0.0.1" || cleanHostIP == "::1" {
			return &domain.Remediation{
				Status: domain.RemediationUnsupported,
				Reason: "Docker Compose service is already bound to loopback.",
			}
		}

		fi, err := os.Stat(exp.Config.File)
		if err != nil || fi.IsDir() {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: fmt.Sprintf("Compose file does not exist on disk: %s", exp.Config.File),
			}
		}

		data, err := os.ReadFile(exp.Config.File)
		if err != nil {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: fmt.Sprintf("Failed to read Compose file: %v", err),
			}
		}

		if _, err := FindTargetPort(data, exp.Config.Service, exp.Config.Line, exp.Port); err != nil {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: fmt.Sprintf("Cannot uniquely locate Compose port in AST: %v", err),
			}
		}

		if exp.Recommendation == nil || exp.Recommendation.Suggested == "" {
			return &domain.Remediation{
				Status: domain.RemediationUnsafe,
				Reason: "No remediation suggestion generated.",
			}
		}

		fp := ComputeBytesFingerprint(exp.Config.File, fi.Size(), data)

		// If container attribution was inferred from Docker metadata (not direct socket ownership):
		// Diff preview is available as TENTATIVE in dry-run mode, but live modification is blocked.
		if exp.Container != nil && exp.Container.AttributionMode == domain.AttributionInferred {
			return &domain.Remediation{
				Status:      domain.RemediationTentative,
				Type:        "bind_localhost",
				File:        exp.Config.File,
				Line:        exp.Config.Line,
				Service:     exp.Config.Service,
				Before:      exp.Recommendation.Current,
				After:       exp.Recommendation.Suggested,
				Reason:      "Socket attribution is inferred from Docker metadata without direct process ownership proof. Live modification is blocked; dry-run preview is tentative.",
				Fingerprint: fp,
			}
		}

		return &domain.Remediation{
			Status:      domain.RemediationSupported,
			Type:        "bind_localhost",
			File:        exp.Config.File,
			Line:        exp.Config.Line,
			Service:     exp.Config.Service,
			Before:      exp.Recommendation.Current,
			After:       exp.Recommendation.Suggested,
			Reason:      fmt.Sprintf("Docker Compose publishes host port to all network interfaces. Remediate to bind to localhost (127.0.0.1) in %s.", exp.Config.File),
			Fingerprint: fp,
		}
	}

	return &domain.Remediation{
		Status: domain.RemediationUnsafe,
		Reason: "Exposure type is not recognized for automated remediation.",
	}
}
