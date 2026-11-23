package cli

import (
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
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
}
