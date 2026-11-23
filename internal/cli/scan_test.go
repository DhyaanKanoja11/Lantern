package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/exposure"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
)

func TestIsWildcardAddress(t *testing.T) {
	wildcards := []string{
		"0.0.0.0",
		"::",
		"*",
		"[::]",
		"0:0:0:0:0:0:0:0",
	}
	for _, addr := range wildcards {
		if !isWildcardAddress(addr) {
			t.Errorf("expected isWildcardAddress(%q) to be true, got false", addr)
		}
	}

	nonWildcards := []string{
		"127.0.0.1",
		"::1",
		"localhost",
		"192.168.1.100",
		"10.0.0.1",
		"172.17.0.1",
	}
	for _, addr := range nonWildcards {
		if isWildcardAddress(addr) {
			t.Errorf("expected isWildcardAddress(%q) to be false, got true", addr)
		}
	}
}

func TestEvaluateWildcardViolations_NoViolations(t *testing.T) {
	summaries := []domain.ExposureSummary{
		{Port: 5432, Address: "127.0.0.1", ProcessName: "postgres"},
		{Port: 6379, Address: "::1", ProcessName: "redis"},
	}

	violations := evaluateWildcardViolations(summaries, nil)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(violations))
	}
}

func TestEvaluateWildcardViolations_DetectsWildcards(t *testing.T) {
	summaries := []domain.ExposureSummary{
		{Port: 5432, Address: "0.0.0.0", ProcessName: "postgres"},
		{Port: 6379, Address: "::", ProcessName: "redis"},
		{Port: 8080, Address: "127.0.0.1", ProcessName: "app"},
	}

	violations := evaluateWildcardViolations(summaries, nil)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
	if violations[0].Port != 5432 || violations[1].Port != 6379 {
		t.Errorf("unexpected violation ports: %v", violations)
	}
}

func TestEvaluateWildcardViolations_WithIgnoredPorts(t *testing.T) {
	summaries := []domain.ExposureSummary{
		{Port: 80, Address: "0.0.0.0", ProcessName: "nginx"},
		{Port: 443, Address: "::", ProcessName: "nginx"},
		{Port: 5432, Address: "0.0.0.0", ProcessName: "postgres"},
	}

	violations := evaluateWildcardViolations(summaries, []int{80, 443})
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Port != 5432 {
		t.Errorf("expected violation on port 5432, got %d", violations[0].Port)
	}
}

func TestScanCmd_Flags(t *testing.T) {
	failFlag := scanCmd.Flags().Lookup("fail-on-wildcard")
	if failFlag == nil {
		t.Fatal("expected flag --fail-on-wildcard to be registered")
	}
	if failFlag.DefValue != "false" {
		t.Errorf("expected default value 'false', got %q", failFlag.DefValue)
	}

	ignoreFlag := scanCmd.Flags().Lookup("ignore-ports")
	if ignoreFlag == nil {
		t.Fatal("expected flag --ignore-ports to be registered")
	}
	if ignoreFlag.DefValue != "[]" {
		t.Errorf("expected default value '[]', got %q", ignoreFlag.DefValue)
	}

	watchFlag := scanCmd.Flags().Lookup("watch")
	if watchFlag == nil {
		t.Fatal("expected flag --watch to be registered")
	}
	if watchFlag.Shorthand != "w" {
		t.Errorf("expected shorthand 'w', got %q", watchFlag.Shorthand)
	}

	intervalFlag := scanCmd.Flags().Lookup("interval")
	if intervalFlag == nil {
		t.Fatal("expected flag --interval to be registered")
	}
	if intervalFlag.DefValue != "2s" {
		t.Errorf("expected default interval '2s', got %q", intervalFlag.DefValue)
	}

	configFlag := scanCmd.Flags().Lookup("config")
	if configFlag == nil {
		t.Fatal("expected flag --config to be registered")
	}
	if configFlag.Shorthand != "c" {
		t.Errorf("expected shorthand 'c', got %q", configFlag.Shorthand)
	}
}

func TestRunScanWatch_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cmd := scanCmd
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)

	analyzer := exposure.NewDefaultAnalyzer()
	formatter := output.NewTextFormatter()

	err := runScanWatch(ctx, cmd, analyzer, formatter, 100*time.Millisecond, false, nil)
	if err != nil {
		t.Fatalf("expected clean exit on cancelled context, got error: %v", err)
	}

	if !bytes.Contains(outBuf.Bytes(), []byte("Lantern Watch Mode")) {
		t.Errorf("expected output to contain watch mode header, got: %s", outBuf.String())
	}
}

func TestWriteGitHubStepSummary(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "lantern_step_summary_*.md")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	t.Setenv("GITHUB_STEP_SUMMARY", tmpFile.Name())

	summaries := []domain.ExposureSummary{
		{Port: 80, Protocol: "tcp", Address: "0.0.0.0", ProcessName: "nginx", Reachability: "Wildcard"},
		{Port: 5432, Protocol: "tcp", Address: "0.0.0.0", ProcessName: "postgres", ContainerName: "pg_db", Reachability: "Wildcard"},
		{Port: 6379, Protocol: "tcp", Address: "127.0.0.1", ProcessName: "redis", Reachability: "localhost only"},
	}
	violations := []domain.ExposureSummary{
		summaries[1],
	}

	writeGitHubStepSummary(summaries, violations, []int{80})

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read step summary: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "Lantern Port Exposure Report") {
		t.Errorf("expected header in summary, got: %s", content)
	}
	if !strings.Contains(content, "| `5432` |") || !strings.Contains(content, "❌ **Violation**") {
		t.Errorf("expected violation entry for port 5432, got: %s", content)
	}
	if !strings.Contains(content, "| `80` |") || !strings.Contains(content, "⚪ *Whitelisted*") {
		t.Errorf("expected whitelisted entry for port 80, got: %s", content)
	}
	if !strings.Contains(content, "| `6379` |") || !strings.Contains(content, "✅ Clean") {
		t.Errorf("expected clean entry for port 6379, got: %s", content)
	}
}

type mockScanAnalyzer struct {
	report *domain.ScanReport
	err    error
}

func (m *mockScanAnalyzer) ScanReport(ctx context.Context) (*domain.ScanReport, error) {
	return m.report, m.err
}

func (m *mockScanAnalyzer) Scan(ctx context.Context) ([]domain.ExposureSummary, error) {
	if m.report != nil {
		return m.report.Summaries, m.err
	}
	return nil, m.err
}

func (m *mockScanAnalyzer) Why(ctx context.Context, port uint16, projectDir string) (*domain.Exposure, error) {
	return nil, nil
}

func TestRunScanOnce_Formats(t *testing.T) {
	ctx := context.Background()
	cmd := scanCmd

	mockAn := &mockScanAnalyzer{
		report: &domain.ScanReport{
			Summaries: []domain.ExposureSummary{
				{
					Port:         5432,
					Protocol:     "tcp",
					Address:      "0.0.0.0",
					ProcessName:  "docker-proxy",
					Reachability: "PUBLIC",
				},
			},
		},
	}

	// Test JSON Formatter
	var jsonBuf bytes.Buffer
	cmd.SetOut(&jsonBuf)
	jsonFormatter := output.NewJSONFormatter()
	if err := runScanOnce(ctx, cmd, mockAn, jsonFormatter, false, nil); err != nil {
		t.Fatalf("runScanOnce with JSON formatter failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), "\"summaries\"") {
		t.Errorf("expected json output to contain \"summaries\", got: %s", jsonBuf.String())
	}

	// Test SARIF Formatter
	var sarifBuf bytes.Buffer
	cmd.SetOut(&sarifBuf)
	sarifFormatter := output.NewSarifFormatter("0.2.1")
	if err := runScanOnce(ctx, cmd, mockAn, sarifFormatter, false, nil); err != nil {
		t.Fatalf("runScanOnce with SARIF formatter failed: %v", err)
	}
	if !strings.Contains(sarifBuf.String(), "\"version\": \"2.1.0\"") {
		t.Errorf("expected SARIF output to contain version 2.1.0, got: %s", sarifBuf.String())
	}
}
