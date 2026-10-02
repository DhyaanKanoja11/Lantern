package compose

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lantern/internal/domain"
)

func TestResolver_ServiceIdentification(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	composeContent := `
services:
  api:
    image: myapi
    ports:
      - "8080:8080"
  worker:
    image: myworker
    ports:
      - "9090:9090"
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatalf("failed to write test compose: %v", err)
	}

	resolver := NewDefaultResolver()

	container := &domain.Container{
		Name: "test-api",
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "api",
		},
	}

	// 1. Port 8080 should match service "api" with certainty
	evidences, err := resolver.FindPortEvidence(context.Background(), container, "", 8080)
	if err != nil {
		t.Fatalf("unexpected error finding port 8080: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidences))
	}
	if evidences[0].Service != "api" || !evidences[0].Certain {
		t.Errorf("expected certain match for service 'api', got %+v", evidences[0])
	}

	// 2. Querying port 9090 for container "api" should return ErrNoMatchingPort
	_, errWorker := resolver.FindPortEvidence(context.Background(), container, "", 9090)
	if !errors.Is(errWorker, ErrNoMatchingPort) {
		t.Errorf("expected ErrNoMatchingPort for container 'api' on port 9090, got %v", errWorker)
	}
}

func TestResolver_MultipleComposeFiles(t *testing.T) {
	tempDir := t.TempDir()
	f1 := filepath.Join(tempDir, "docker-compose.yml")
	f2 := filepath.Join(tempDir, "docker-compose.override.yml")

	c1 := `
services:
  web:
    ports:
      - "80:80"
`
	c2 := `
services:
  web:
    ports:
      - "80:80"
`
	if err := os.WriteFile(f1, []byte(c1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte(c2), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Name: "test-web",
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": "docker-compose.yml,docker-compose.override.yml",
			"com.docker.compose.service":              "web",
		},
	}

	// FindPortEvidence must inspect both files and preserve file ordering
	evidences, err := resolver.FindPortEvidence(context.Background(), container, "", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 2 {
		t.Fatalf("expected 2 evidences from multiple files, got %d", len(evidences))
	}
	if evidences[0].File != f1 {
		t.Errorf("expected first evidence from %s, got %s", f1, evidences[0].File)
	}
	if evidences[1].File != f2 {
		t.Errorf("expected second evidence from %s, got %s", f2, evidences[1].File)
	}

	// ResolveAttribution should flag ambiguity when multiple declarations exist
	_, errResolve := resolver.ResolveAttribution(context.Background(), container, 80)
	if !errors.Is(errResolve, ErrAmbiguousAttribution) {
		t.Errorf("expected ErrAmbiguousAttribution, got %v", errResolve)
	}
}

func TestResolver_ProjectWorkingDirResolution(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "compose.yaml")
	content := `
services:
  app:
    ports:
      - "3000:3000"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": "compose.yaml", // Relative path!
			"com.docker.compose.service":              "app",
		},
	}

	evidences, err := resolver.FindPortEvidence(context.Background(), container, "", 3000)
	if err != nil {
		t.Fatalf("unexpected error resolving relative path: %v", err)
	}
	if len(evidences) != 1 || evidences[0].File != composePath {
		t.Errorf("expected resolved file %s, got %+v", composePath, evidences)
	}
}

func TestResolver_MissingComposeFile(t *testing.T) {
	tempDir := t.TempDir()
	resolver := NewDefaultResolver()

	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": "does-not-exist.yml",
		},
	}

	_, err := resolver.FindPortEvidence(context.Background(), container, "", 80)
	if !errors.Is(err, ErrComposeFileNotFound) {
		t.Errorf("expected ErrComposeFileNotFound, got %v", err)
	}
}

func TestResolver_NoMatchingPort(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "compose.yml")
	content := `
services:
  db:
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
	}

	_, err := resolver.FindPortEvidence(context.Background(), container, "", 9999)
	if !errors.Is(err, ErrNoMatchingPort) {
		t.Errorf("expected ErrNoMatchingPort, got %v", err)
	}
}

func TestResolver_MultipleMatchingServices_Ambiguity(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	content := `
services:
  db1:
    ports:
      - "5432:5432"
  db2:
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	// Container without explicit service label
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
		},
	}

	evidences, err := resolver.FindPortEvidence(context.Background(), container, "", 5432)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 2 {
		t.Fatalf("expected 2 ambiguous evidences, got %d", len(evidences))
	}
	for _, ev := range evidences {
		if ev.Certain {
			t.Errorf("ambiguous evidence must not be marked Certain: %+v", ev)
		}
	}

	_, errResolve := resolver.ResolveAttribution(context.Background(), container, 5432)
	if !errors.Is(errResolve, ErrAmbiguousAttribution) {
		t.Errorf("expected ErrAmbiguousAttribution, got %v", errResolve)
	}
}

func TestResolver_LocalhostVsWildcardDistinction(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	content := `
services:
  db:
    ports:
      - "127.0.0.1:5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
	}

	// 1. Wildcard 0.0.0.0 query must NOT match explicit 127.0.0.1 binding
	_, errWildcard := resolver.FindPortEvidence(context.Background(), container, "0.0.0.0", 5432)
	if !errors.Is(errWildcard, ErrNoMatchingPort) {
		t.Errorf("expected ErrNoMatchingPort for 0.0.0.0 query against 127.0.0.1, got %v", errWildcard)
	}

	// 2. Explicit 127.0.0.1 query must match
	evidences, errLocal := resolver.FindPortEvidence(context.Background(), container, "127.0.0.1", 5432)
	if errLocal != nil {
		t.Fatalf("unexpected error for 127.0.0.1 match: %v", errLocal)
	}
	if len(evidences) != 1 || evidences[0].HostIP != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1 evidence, got %+v", evidences)
	}
}

func TestResolver_AbsoluteConfigFilePath(t *testing.T) {
	tempDir := t.TempDir()
	absPath := filepath.Join(tempDir, "docker-compose.yaml")
	content := `
services:
  web:
    ports:
      - "80:80"
`
	if err := os.WriteFile(absPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.config_files": absPath, // Absolute!
			"com.docker.compose.service":              "web",
		},
	}

	evidences, err := resolver.FindPortEvidence(context.Background(), container, "", 80)
	if err != nil {
		t.Fatalf("unexpected error with absolute path: %v", err)
	}
	if len(evidences) != 1 || evidences[0].File != absPath {
		t.Errorf("expected evidence for %s, got %+v", absPath, evidences)
	}
}

func TestResolver_NoFilesystemMutation(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	originalContent := []byte(`
services:
  immutable:
    image: test
    ports:
      - "4000:4000"
`)
	if err := os.WriteFile(composePath, originalContent, 0644); err != nil {
		t.Fatal(err)
	}

	beforeHash := sha256.Sum256(originalContent)
	beforeInfo, err := os.Stat(composePath)
	if err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "immutable",
		},
	}

	_, errFind := resolver.FindPortEvidence(context.Background(), container, "", 4000)
	if errFind != nil {
		t.Fatalf("unexpected error: %v", errFind)
	}

	// Verify file was not mutated
	afterContent, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	afterHash := sha256.Sum256(afterContent)
	afterInfo, err := os.Stat(composePath)
	if err != nil {
		t.Fatal(err)
	}

	if beforeHash != afterHash {
		t.Errorf("file was mutated! hash mismatch")
	}
	if beforeInfo.Size() != afterInfo.Size() {
		t.Errorf("file size changed from %d to %d", beforeInfo.Size(), afterInfo.Size())
	}
}

func TestResolver_MetadataUnavailable(t *testing.T) {
	resolver := NewResolverWithReader(nil, t.TempDir()) // empty temp dir has no compose files

	_, err := resolver.FindPortEvidence(context.Background(), nil, "", 80)
	if !errors.Is(err, ErrComposeMetadataUnavailable) {
		t.Errorf("expected ErrComposeMetadataUnavailable for nil container with no compose files, got %v", err)
	}
}

func TestResolver_EphemeralPort_CasesABC(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	content := `
services:
  db:
    ports:
      - "5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()

	// Case A: Compose "5432", Docker mapping: none, Query hostPort: 5432 -> NO MATCH
	containerA := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
		Ports: nil,
	}
	_, errA := resolver.FindPortEvidence(context.Background(), containerA, "", 5432)
	if !errors.Is(errA, ErrNoMatchingPort) {
		t.Errorf("Case A: expected ErrNoMatchingPort when no Docker mapping exists, got %v", errA)
	}

	// Case B: Compose "5432", Docker mapping: HostPort=49153, ContainerPort=5432, Query hostPort: 49153 -> MATCH
	containerB := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
		Ports: []domain.PortMapping{
			{HostIP: "0.0.0.0", HostPort: 49153, ContainerPort: 5432, Protocol: "tcp"},
		},
	}
	evsB, errB := resolver.FindPortEvidence(context.Background(), containerB, "", 49153)
	if errB != nil {
		t.Fatalf("Case B: unexpected error: %v", errB)
	}
	if len(evsB) != 1 {
		t.Fatalf("Case B: expected 1 evidence, got %d", len(evsB))
	}
	if evsB[0].HostPort != 49153 || evsB[0].ContainerPort != 5432 {
		t.Errorf("Case B: expected HostPort=49153, ContainerPort=5432, got %+v", evsB[0])
	}

	// Case C: Compose "5432", Docker mapping: HostPort=49153, ContainerPort=3306, Query hostPort: 49153 -> NO MATCH
	containerC := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
		Ports: []domain.PortMapping{
			{HostIP: "0.0.0.0", HostPort: 49153, ContainerPort: 3306, Protocol: "tcp"},
		},
	}
	_, errC := resolver.FindPortEvidence(context.Background(), containerC, "", 49153)
	if !errors.Is(errC, ErrNoMatchingPort) {
		t.Errorf("Case C: expected ErrNoMatchingPort when ContainerPort mismatch, got %v", errC)
	}
}

func TestResolver_ResolveAttribution_DockerHostIP_Disambiguation(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	// Compose defines both 127.0.0.1:5432:5432 and 0.0.0.0:5432:5432
	content := `
services:
  db:
    ports:
      - "127.0.0.1:5432:5432"
      - "0.0.0.0:5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()

	// Container Docker mapping has HostIP: 127.0.0.1, HostPort: 5432
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
		Ports: []domain.PortMapping{
			{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
		},
	}

	// ResolveAttribution should use the Docker HostIP (127.0.0.1) and resolve to the exact matching declaration
	evidence, err := resolver.ResolveAttribution(context.Background(), container, 5432)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evidence == nil {
		t.Fatalf("expected evidence, got nil")
	}
	if evidence.HostIP != "127.0.0.1" {
		t.Errorf("expected evidence HostIP '127.0.0.1', got %s", evidence.HostIP)
	}
	if evidence.Line != 5 {
		t.Errorf("expected line 5 for 127.0.0.1 declaration, got line %d", evidence.Line)
	}
}

func TestResolver_ResolveAttribution_DockerHostIP_ConflictingMappings(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	content := `
services:
  db:
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	resolver := NewDefaultResolver()

	// Container Docker metadata has conflicting HostIPs for the same hostPort 5432
	container := &domain.Container{
		Labels: map[string]string{
			"com.docker.compose.project.working_dir":  tempDir,
			"com.docker.compose.project.config_files": composePath,
			"com.docker.compose.service":              "db",
		},
		Ports: []domain.PortMapping{
			{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
			{HostIP: "192.168.1.50", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
		},
	}

	// ResolveAttribution must preserve ambiguity and NOT arbitrarily pick one
	_, err := resolver.ResolveAttribution(context.Background(), container, 5432)
	if !errors.Is(err, ErrAmbiguousAttribution) {
		t.Errorf("expected ErrAmbiguousAttribution for conflicting HostIP mappings, got %v", err)
	}
}
