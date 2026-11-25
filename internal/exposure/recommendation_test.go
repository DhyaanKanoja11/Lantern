package exposure

import (
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/explain"
)

func TestGenerateRecommendation_KeepsOriginalDeclarationShape(t *testing.T) {
	cases := []struct {
		original string
		hostPort uint16
		cPort    uint16
		want     string
	}{
		{"5432:5432", 5432, 5432, "127.0.0.1:5432:5432"},
		{"8080-8085:80-85", 8082, 80, "127.0.0.1:8080-8085:80-85"},
		{"53:53/udp", 53, 53, "127.0.0.1:53:53/udp"},
		{"0.0.0.0:9000:9000/tcp", 9000, 9000, "127.0.0.1:9000:9000/tcp"},
		{"[::]:6379:6379", 6379, 6379, "127.0.0.1:6379:6379"},
	}

	for _, tc := range cases {
		t.Run(tc.original, func(t *testing.T) {
			exp := &domain.Exposure{
				Port: tc.hostPort,
				Config: &domain.ConfigEvidence{
					File:          "docker-compose.yml",
					Original:      tc.original,
					Evidence:      "web: " + tc.original,
					HostPort:      tc.hostPort,
					ContainerPort: tc.cPort,
				},
			}
			rec := GenerateRecommendation(exp, explain.RootCause{Type: explain.RootCauseComposePublishedPort})
			if rec == nil {
				t.Fatal("expected a recommendation")
			}
			if rec.Suggested != tc.want {
				t.Errorf("suggested %q, want %q", rec.Suggested, tc.want)
			}
		})
	}
}

func TestGenerateRecommendation_NoSuggestionForUnparseableOriginal(t *testing.T) {
	exp := &domain.Exposure{
		Port: 5432,
		Config: &domain.ConfigEvidence{
			File:          "docker-compose.yml",
			Original:      "published: 5432, target: 5432, protocol: tcp",
			HostPort:      5432,
			ContainerPort: 5432,
		},
	}
	if rec := GenerateRecommendation(exp, explain.RootCause{Type: explain.RootCauseComposePublishedPort}); rec != nil {
		t.Fatalf("expected no recommendation for long syntax, got %+v", rec)
	}
}

// Rewriting "${PORT:-80}:80" to a literal would throw away the variable, so
// interpolated declarations never get an automatic suggestion.
func TestGenerateRecommendation_NoSuggestionForInterpolatedPort(t *testing.T) {
	exp := &domain.Exposure{
		Port: 80,
		Config: &domain.ConfigEvidence{
			File:          "docker-compose.yml",
			Original:      "${PORT:-80}:80",
			HostPort:      80,
			ContainerPort: 80,
			Interpolated:  true,
		},
	}
	if rec := GenerateRecommendation(exp, explain.RootCause{Type: explain.RootCauseComposePublishedPort}); rec != nil {
		t.Fatalf("expected no recommendation, got %+v", rec)
	}
}
