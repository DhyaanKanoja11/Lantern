package exposure

import (
	"fmt"
	"strings"

	"lantern/internal/domain"
	"lantern/internal/explain"
)

// GenerateRecommendation computes a safe remediation recommendation if supported by evidence.
func GenerateRecommendation(exp *domain.Exposure, rc explain.RootCause) *domain.Recommendation {
	if exp == nil {
		return nil
	}

	// 1. If exposure was caused by Docker Compose publishing to wildcard or all interfaces
	if rc.Type == explain.RootCauseComposePublishedPort && exp.Config != nil {
		cleanHostIP := strings.Trim(strings.TrimSpace(exp.Config.HostIP), "[]")
		// If already bound strictly to loopback, no change needed
		if cleanHostIP == "127.0.0.1" || cleanHostIP == "::1" {
			return nil
		}

		hPort := exp.Config.HostPort
		if hPort == 0 && exp.DockerMapping != nil {
			hPort = exp.DockerMapping.HostPort
		}
		cPort := exp.Config.ContainerPort
		if cPort == 0 && exp.DockerMapping != nil {
			cPort = exp.DockerMapping.ContainerPort
		}

		if hPort > 0 && cPort > 0 {
			suggested := fmt.Sprintf("127.0.0.1:%d:%d", hPort, cPort)
			current := exp.Config.Evidence
			if current == "" {
				current = fmt.Sprintf("%d:%d", hPort, cPort)
			}
			return &domain.Recommendation{
				Type:        "bind_localhost",
				Current:     current,
				Suggested:   suggested,
				Description: fmt.Sprintf("Bind published port to localhost (127.0.0.1) in %s to prevent local network exposure.", exp.Config.File),
			}
		}
	}

	// 2. If exposure is a native process bound to a wildcard address (0.0.0.0 or ::)
	if rc.Type == explain.RootCauseProcessWildcardBind && exp.Port > 0 {
		return &domain.Recommendation{
			Type:        "bind_localhost",
			Current:     fmt.Sprintf("%s:%d", exp.BindAddress, exp.Port),
			Suggested:   fmt.Sprintf("127.0.0.1:%d", exp.Port),
			Description: "Configure application to bind strictly to loopback (127.0.0.1) instead of wildcard address.",
		}
	}

	return nil
}
