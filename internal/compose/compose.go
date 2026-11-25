package compose

import (
	"context"
	"errors"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

var (
	// ErrComposeMetadataUnavailable indicates the container lacked Compose labels or configuration metadata.
	ErrComposeMetadataUnavailable = errors.New("compose metadata unavailable")
	// ErrComposeFileNotFound indicates specified or predictable Compose files were not found.
	ErrComposeFileNotFound = errors.New("compose file not found")
	// ErrComposeFileUnreadable indicates an existing Compose file could not be read.
	ErrComposeFileUnreadable = errors.New("compose file unreadable")
	// ErrInvalidYAML indicates the Compose file contains malformed YAML syntax.
	ErrInvalidYAML = errors.New("invalid compose yaml")
	// ErrUnresolvedInterpolation means a candidate declaration uses a
	// variable (e.g. "${PORT}:80") that couldn't be resolved, so we can't
	// tell whether it's the one publishing the port.
	ErrUnresolvedInterpolation = errors.New("compose port uses variable interpolation that could not be resolved")
	// ErrNoMatchingPort indicates no Compose port declaration matched the requested port.
	ErrNoMatchingPort = errors.New("no matching compose port declaration")
	// ErrAmbiguousAttribution indicates multiple services or declarations ambiguously claim the port.
	ErrAmbiguousAttribution = errors.New("ambiguous compose port attribution: multiple matching declarations")
)

// ComposeResolver defines the interface for attributing port mappings to Compose configuration files.
type ComposeResolver interface {
	ResolveAttribution(ctx context.Context, container *domain.Container, hostPort uint16) (*domain.ConfigEvidence, error)
}

// ComposeInspector defines the interface for finding port evidence across Compose files.
type ComposeInspector interface {
	FindPortEvidence(ctx context.Context, container *domain.Container, hostAddress string, hostPort uint16) ([]domain.ConfigEvidence, error)
}
