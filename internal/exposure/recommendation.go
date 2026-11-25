package exposure

import (
	"fmt"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/compose"
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/explain"
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

		// Build the suggestion from what's actually written in the file so
		// ranges and /proto suffixes survive. If we can't, say nothing rather
		// than suggest something that changes the mapping.
		// Never rewrite a line that uses variables: a literal would silently
		// replace the user's ${VAR} and the value we resolved may be stale.
		if exp.Config.Interpolated {
			return nil
		}
		original := exp.Config.Original
		if original == "" {
			original = exp.Config.Evidence
		}
		suggested, err := compose.BindToLoopback(original)
		if err != nil {
			return nil
		}
		return &domain.Recommendation{
			Type:        "bind_localhost",
			Current:     original,
			Suggested:   suggested,
			Description: fmt.Sprintf("Bind published port to localhost (127.0.0.1) in %s to prevent local network exposure.", exp.Config.File),
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
