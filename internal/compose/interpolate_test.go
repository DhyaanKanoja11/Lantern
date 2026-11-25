package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestParseComposeFile_InterpolatedPorts(t *testing.T) {
	t.Setenv("LANTERN_TEST_PORT", "8081")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("# comment\nexport FROM_DOTENV=6000\nQUOTED=\"7000\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "docker-compose.yml")
	data := []byte(`services:
  app:
    ports:
      - "${DB_PORT_LANTERN_UNSET:-5432}:5432"
      - "${LANTERN_TEST_PORT}:80"
      - "127.0.0.1:${FROM_DOTENV}:6000"
      - "${QUOTED}:7000/udp"
      - "${NOPE_LANTERN_UNSET}:9000"
`)

	got, err := ParseComposeFile(path, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("expected all 5 declarations to be reported, got %d: %+v", len(got), got)
	}

	want := []struct {
		host       uint16
		unresolved bool
	}{{5432, false}, {8081, false}, {6000, false}, {7000, false}, {0, true}}
	for i, w := range want {
		e := got[i]
		if !e.Interpolated {
			t.Errorf("line %d: expected Interpolated", e.Line)
		}
		if e.Unresolved != w.unresolved {
			t.Errorf("line %d: Unresolved=%v, want %v", e.Line, e.Unresolved, w.unresolved)
		}
		if e.Port.HostPortStart != w.host {
			t.Errorf("line %d: host port %d, want %d", e.Line, e.Port.HostPortStart, w.host)
		}
	}
	if got[0].Original != "${DB_PORT_LANTERN_UNSET:-5432}:5432" {
		t.Errorf("Original should keep the text as written, got %q", got[0].Original)
	}
	if got[3].Port.Protocol != "udp" {
		t.Errorf("protocol lost: %+v", got[3].Port)
	}
}

func TestResolver_InterpolatedPortIsNeverCertain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  db:\n    ports:\n      - \"${PG_LANTERN_UNSET:-5432}:5432\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.config_files": path,
			"com.docker.compose.service":              "db",
		},
		Ports: []domain.PortMapping{{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}},
	}
	ev, err := NewDefaultResolver().ResolveAttribution(context.Background(), container, 5432)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Certain || !ev.Interpolated {
		t.Errorf("interpolated evidence must be uncertain and flagged, got %+v", ev)
	}
}

func TestResolver_UnresolvedInterpolationIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  db:\n    ports:\n      - \"${PG_LANTERN_UNSET}:5432\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.config_files": path,
			"com.docker.compose.service":              "db",
		},
	}
	_, err := NewDefaultResolver().ResolveAttribution(context.Background(), container, 5432)
	if !errors.Is(err, ErrUnresolvedInterpolation) {
		t.Fatalf("expected ErrUnresolvedInterpolation, got %v", err)
	}
}
