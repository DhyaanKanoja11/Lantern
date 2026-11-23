package output

import (
	"encoding/json"
	"io"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// JSONFormatter renders structured JSON output for automated tooling.
type JSONFormatter struct{}

// NewJSONFormatter creates a new instance of JSONFormatter.
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// RenderScan formats scan results and notices as indented JSON.
func (j *JSONFormatter) RenderScan(w io.Writer, list []domain.ExposureSummary, notices ...string) error {
	report := domain.ScanReport{
		Summaries: list,
		Notices:   notices,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderWhy formats an exposure causality result as indented JSON.
func (j *JSONFormatter) RenderWhy(w io.Writer, exp *domain.Exposure) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(exp)
}
