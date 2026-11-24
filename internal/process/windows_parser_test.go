package process

import (
	"strings"
	"testing"
)

func TestParseTasklistCSV_Valid(t *testing.T) {
	sample := `"ollama.exe","22372","Console","1","50,152 K"`
	proc, err := ParseTasklistCSV(strings.NewReader(sample), 22372)
	if err != nil {
		t.Fatalf("unexpected error parsing tasklist CSV: %v", err)
	}

	if proc.PID != 22372 {
		t.Errorf("expected PID 22372, got %d", proc.PID)
	}
	if proc.Name != "ollama.exe" {
		t.Errorf("expected name ollama.exe, got %q", proc.Name)
	}
}

func TestParseTasklistCSV_NoMatch(t *testing.T) {
	sample := `INFO: No tasks are running which match the specified criteria.`
	_, err := ParseTasklistCSV(strings.NewReader(sample), 99999)
	if err == nil {
		t.Fatal("expected error for no match, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %v", err)
	}
}

func TestParseTasklistCSV_Empty(t *testing.T) {
	_, err := ParseTasklistCSV(strings.NewReader(""), 1234)
	if err == nil {
		t.Fatal("expected error for empty CSV, got nil")
	}
}
