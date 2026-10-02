package output

import (
	"io"
	"lantern/internal/domain"
)

// Formatter renders exposure results for CLI presentation.
type Formatter interface {
	RenderWhy(w io.Writer, exp *domain.Exposure) error
	RenderScan(w io.Writer, list []domain.ExposureSummary) error
}
