package exposure

import (
	"context"
	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

// Analyzer defines the core engine interface for analyzing service reachability.
type Analyzer interface {
	Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error)
	WhyWithProto(ctx context.Context, port uint16, proto string, projectDir string) (*domain.Exposure, error)
	Scan(ctx context.Context) ([]domain.ExposureSummary, error)
	ScanReport(ctx context.Context) (*domain.ScanReport, error)
}
