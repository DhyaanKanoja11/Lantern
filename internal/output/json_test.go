package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestJSONFormatter_RenderScan(t *testing.T) {
	formatter := NewJSONFormatter()
	buf := new(bytes.Buffer)

	list := []domain.ExposureSummary{
		{
			Port:          5432,
			Protocol:      "tcp",
			Address:       "0.0.0.0",
			ProcessName:   "docker-proxy",
			ContainerName: "db-1",
			Reachability:  "PUBLIC",
		},
	}

	err := formatter.RenderScan(buf, list, "Docker desktop active")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report domain.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}

	if len(report.Summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(report.Summaries))
	}
	if report.Summaries[0].Port != 5432 {
		t.Errorf("expected port 5432, got %d", report.Summaries[0].Port)
	}
	if len(report.Notices) != 1 || report.Notices[0] != "Docker desktop active" {
		t.Errorf("unexpected notices: %v", report.Notices)
	}
}

func TestJSONFormatter_RenderWhy(t *testing.T) {
	formatter := NewJSONFormatter()
	buf := new(bytes.Buffer)

	exp := &domain.Exposure{
		Port:        8080,
		Protocol:    "tcp",
		BindAddress: "127.0.0.1",
		Reachability: domain.Reachability{
			Local: true,
			State: "LOOPBACK_ONLY",
		},
	}

	err := formatter.RenderWhy(buf, exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed domain.Exposure
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}

	if parsed.Port != 8080 {
		t.Errorf("expected port 8080, got %d", parsed.Port)
	}
	if parsed.BindAddress != "127.0.0.1" {
		t.Errorf("expected bind address 127.0.0.1, got %s", parsed.BindAddress)
	}
}
