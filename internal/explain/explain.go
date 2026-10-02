package explain

import (
	"lantern/internal/domain"
)

// Explainer formats the exposure path as an ASCII tree.
type Explainer interface {
	FormatPath(exp *domain.Exposure) string
}
