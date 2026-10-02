package explain

import (
	"lantern/internal/domain"
)

// Explainer generates structured explanations and formats exposure paths.
type Explainer interface {
	Explain(exp *domain.Exposure) *Explanation
	FormatPath(exp *domain.Exposure) string
}

// DefaultExplainer implements the Explainer interface.
type DefaultExplainer struct{}

// NewDefaultExplainer creates a new default instance of Explainer.
func NewDefaultExplainer() Explainer {
	return &DefaultExplainer{}
}

// Explain produces a full structured explanation for an exposure.
func (e *DefaultExplainer) Explain(exp *domain.Exposure) *Explanation {
	return Explain(exp)
}

// FormatPath renders the exposure path as an ASCII tree.
func (e *DefaultExplainer) FormatPath(exp *domain.Exposure) string {
	return FormatPath(exp)
}
