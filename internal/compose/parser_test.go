package compose

import (
	"errors"
	"testing"
)

func TestParseComposeFile_ExactLineNumbers(t *testing.T) {
	// Source YAML with known line numbers:
	// Line 1: version: "3.8"
	// Line 2:
	// Line 3: services:
	// Line 4:   web:
	// Line 5:     image: nginx
	// Line 6:     ports:
	// Line 7:       - "80:80"
	// Line 8:       - "443:443"
	// Line 9:   db:
	// Line 10:    image: postgres:15
	// Line 11:    ports:
	// Line 12:      - target: 5432
	// Line 13:        published: 5432
	// Line 14:        protocol: tcp
	yamlContent := `version: "3.8"

services:
  web:
    image: nginx
    ports:
      - "80:80"
      - "443:443"
  db:
    image: postgres:15
    ports:
      - target: 5432
        published: 5432
        protocol: tcp
`

	evidences, err := ParseComposeFile("docker-compose.yml", []byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 3 {
		t.Fatalf("expected 3 port declarations, got %d", len(evidences))
	}

	// Verify line 7 for "80:80"
	e1 := evidences[0]
	if e1.Service != "web" || e1.Line != 7 || e1.Port.HostPortStart != 80 {
		t.Errorf("e1 unexpected: %+v (want line 7)", e1)
	}

	// Verify line 8 for "443:443"
	e2 := evidences[1]
	if e2.Service != "web" || e2.Line != 8 || e2.Port.HostPortStart != 443 {
		t.Errorf("e2 unexpected: %+v (want line 8)", e2)
	}

	// Verify line 12 for long syntax target: 5432
	e3 := evidences[2]
	if e3.Service != "db" || e3.Line != 12 || e3.Port.HostPortStart != 5432 {
		t.Errorf("e3 unexpected: %+v (want line 12)", e3)
	}
}

func TestParseComposeFile_MultiplePortsInOneService(t *testing.T) {
	yamlContent := `
services:
  proxy:
    image: traefik
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
`
	evidences, err := ParseComposeFile("compose.yaml", []byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 3 {
		t.Fatalf("expected 3 port declarations, got %d", len(evidences))
	}

	ports := []uint16{80, 443, 8080}
	for i, ev := range evidences {
		if ev.Service != "proxy" {
			t.Errorf("expected service 'proxy', got %s", ev.Service)
		}
		if ev.Port.HostPortStart != ports[i] {
			t.Errorf("expected host port %d, got %d", ports[i], ev.Port.HostPortStart)
		}
	}
}

func TestParseComposeFile_InvalidYAML(t *testing.T) {
	invalidYAML := `
services:
  web:
    ports:
      - [unclosed bracket
`
	_, err := ParseComposeFile("broken.yml", []byte(invalidYAML))
	if err == nil {
		t.Fatalf("expected error for invalid YAML, got nil")
	}
	if !errors.Is(err, ErrInvalidYAML) {
		t.Errorf("expected ErrInvalidYAML, got %v", err)
	}
}

func TestParseComposeFile_MalformedPortSafelySkipped(t *testing.T) {
	yamlContent := `
services:
  app:
    image: myapp
    ports:
      - "not-a-port"
      - "3000:3000"
      - "invalid:999999"
`
	evidences, err := ParseComposeFile("compose.yml", []byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the valid port 3000 should be extracted
	if len(evidences) != 1 {
		t.Fatalf("expected 1 valid port declaration, got %d", len(evidences))
	}
	if evidences[0].Port.HostPortStart != 3000 {
		t.Errorf("expected port 3000, got %d", evidences[0].Port.HostPortStart)
	}
}

func TestParseComposeFile_EmptyOrNoServices(t *testing.T) {
	ev1, err1 := ParseComposeFile("empty.yml", []byte(""))
	if err1 != nil || len(ev1) != 0 {
		t.Errorf("expected empty results for empty content, got %v, %d", err1, len(ev1))
	}

	ev2, err2 := ParseComposeFile("no_services.yml", []byte("version: '3.8'\nnetworks:\n  default:\n"))
	if err2 != nil || len(ev2) != 0 {
		t.Errorf("expected empty results for no services, got %v, %d", err2, len(ev2))
	}
}
