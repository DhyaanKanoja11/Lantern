package output

import (
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"io"
)

// Formatter renders exposure results for CLI presentation.
type Formatter interface {
	RenderWhy(w io.Writer, exp *domain.Exposure) error
	RenderScan(w io.Writer, list []domain.ExposureSummary, notices ...string) error
}
