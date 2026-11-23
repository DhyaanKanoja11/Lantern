package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestSarifFormatter_RenderScan_Wildcard(t *testing.T) {
	formatter := NewSarifFormatter("0.2.1")
	buf := new(bytes.Buffer)

	list := []domain.ExposureSummary{
		{
			Port:          5432,
			Protocol:      "tcp",
			Address:       "0.0.0.0",
			ProcessName:   "docker-proxy",
			ContainerName: "my-db",
			Reachability:  "PUBLIC",
		},
		{
			Port:         8080,
			Protocol:     "tcp",
			Address:      "127.0.0.1",
			ProcessName:  "node",
			Reachability: "LOCALHOST",
		},
	}

	err := formatter.RenderScan(buf, list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report SarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", report.Version)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "Lantern" {
		t.Errorf("expected tool name Lantern, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.2.1" {
		t.Errorf("expected tool version 0.2.1, got %s", run.Tool.Driver.Version)
	}

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result (wildcard only), got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "LANTERN001" {
		t.Errorf("expected ruleId LANTERN001, got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected error level, got %s", res.Level)
	}

	if len(res.Locations) != 1 || len(res.Locations[0].LogicalLocations) != 1 {
		t.Fatalf("expected logical location for container")
	}
	if res.Locations[0].LogicalLocations[0].Name != "my-db" {
		t.Errorf("expected container name my-db, got %s", res.Locations[0].LogicalLocations[0].Name)
	}
}

func TestSarifFormatter_RenderScan_Clean(t *testing.T) {
	formatter := NewSarifFormatter("")
	buf := new(bytes.Buffer)

	list := []domain.ExposureSummary{
		{
			Port:         8080,
			Protocol:     "tcp",
			Address:      "127.0.0.1",
			ProcessName:  "node",
			Reachability: "LOCALHOST",
		},
	}

	err := formatter.RenderScan(buf, list)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report SarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for clean localhost listeners, got %d", len(report.Runs[0].Results))
	}
}

func TestSarifFormatter_RenderWhy_WithConfigLocation(t *testing.T) {
	formatter := NewSarifFormatter("0.2.1")
	buf := new(bytes.Buffer)

	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Reachability: domain.Reachability{
			State: "LAN_REACHABLE",
		},
		Container: &domain.Container{
			Name: "postgres-svc",
		},
		Config: &domain.ConfigEvidence{
			File: "docker-compose.yml",
			Line: 12,
		},
	}

	err := formatter.RenderWhy(buf, exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report SarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}

	res := report.Runs[0].Results[0]
	if res.Locations[0].PhysicalLocation == nil {
		t.Fatalf("expected physicalLocation to be populated")
	}
	if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "docker-compose.yml" {
		t.Errorf("expected URI docker-compose.yml, got %s", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if res.Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Errorf("expected startLine 12, got %d", res.Locations[0].PhysicalLocation.Region.StartLine)
	}
}
