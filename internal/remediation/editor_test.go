package remediation

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestModifyComposeBytes_LongForm_InsertHostIP(t *testing.T) {
	input := `# Web service definition
services:
  web:
    image: nginx:alpine
    ports:
      # HTTP frontend
      - target: 80
        published: 8080
        protocol: tcp
        mode: host
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`

	modified, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "web", 7, 8080, "published: 8080, target: 80, host_ip: 127.0.0.1")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)

	// Verify host_ip inserted with proper indentation
	if !strings.Contains(modStr, "        host_ip: 127.0.0.1") {
		t.Errorf("expected inserted '        host_ip: 127.0.0.1', got:\n%s", modStr)
	}

	// Verify comments and other keys preserved
	if !strings.Contains(modStr, "# Web service definition") || !strings.Contains(modStr, "# HTTP frontend") {
		t.Errorf("comments were stripped or corrupted:\n%s", modStr)
	}
	if !strings.Contains(modStr, "mode: host") || !strings.Contains(modStr, "protocol: tcp") {
		t.Errorf("other mapping keys corrupted:\n%s", modStr)
	}

	// Verify other service unchanged
	if !strings.Contains(modStr, `- "5432:5432"`) {
		t.Errorf("unrelated service 'db' altered:\n%s", modStr)
	}
}

func TestModifyComposeBytes_LongForm_RewriteExistingHostIP(t *testing.T) {
	input := `services:
  web:
    image: nginx:alpine
    ports:
      - target: 80
        published: 8080
        host_ip: 0.0.0.0 # bind all
        protocol: tcp
`

	modified, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "web", 5, 8080, "published: 8080, target: 80, host_ip: 127.0.0.1")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)

	if !strings.Contains(modStr, "host_ip: 127.0.0.1 # bind all") {
		t.Errorf("expected 'host_ip: 127.0.0.1 # bind all', got:\n%s", modStr)
	}
	if strings.Contains(modStr, "0.0.0.0") {
		t.Errorf("0.0.0.0 was not completely replaced:\n%s", modStr)
	}
}

func TestModifyComposeBytes_LongForm_QuotedHostIP(t *testing.T) {
	input := `services:
  api:
    image: node:20
    ports:
      - target: 3000
        published: 3000
        host_ip: "0.0.0.0"
`

	modified, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "api", 5, 3000, "published: 3000, target: 3000, host_ip: 127.0.0.1")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)
	if !strings.Contains(modStr, `host_ip: "127.0.0.1"`) {
		t.Errorf("expected preserved quotes 'host_ip: \"127.0.0.1\"', got:\n%s", modStr)
	}
}

func TestModifyComposeBytes_LongForm_FailClosed_Interpolation(t *testing.T) {
	input := `services:
  web:
    image: nginx:alpine
    ports:
      - target: 80
        published: "${PORT}"
`

	_, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "web", 5, 8080, "127.0.0.1")
	if err == nil {
		t.Fatalf("expected error on variable interpolation in published port, got nil")
	}
	if !strings.Contains(err.Error(), "interpolation") {
		t.Errorf("expected interpolation error message, got: %v", err)
	}
}

func TestModifyComposeBytes_LongForm_FailClosed_PortRange(t *testing.T) {
	input := `services:
  cluster:
    image: cluster:latest
    ports:
      - target: 8000
        published: "8000-8005"
`

	_, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "cluster", 5, 8000, "127.0.0.1")
	if err == nil {
		t.Fatalf("expected error on port range in long syntax, got nil")
	}
	if !strings.Contains(err.Error(), "range") {
		t.Errorf("expected range error message, got: %v", err)
	}
}

func TestModifyComposeBytes_LongForm_FailClosed_MissingPublished(t *testing.T) {
	input := `services:
  backend:
    image: app:latest
    ports:
      - target: 8080
        protocol: tcp
`

	_, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "backend", 5, 8080, "127.0.0.1")
	if err == nil {
		t.Fatalf("expected error on missing published port, got nil")
	}
}

func TestModifyComposeBytes_MixedShortAndLongEntries(t *testing.T) {
	input := `services:
  gateway:
    image: traefik:v3.0
    ports:
      # Short syntax
      - "80:80"
      # Long syntax
      - target: 443
        published: 8443
        protocol: tcp
`

	// 1. Remediate the long syntax entry
	mod1, err := ModifyComposeBytes([]byte(input), "docker-compose.yml", "gateway", 8, 8443, "published: 8443, target: 443, host_ip: 127.0.0.1")
	if err != nil {
		t.Fatalf("ModifyComposeBytes on long entry failed: %v", err)
	}
	modStr1 := string(mod1)
	if !strings.Contains(modStr1, "host_ip: 127.0.0.1") {
		t.Errorf("expected host_ip: 127.0.0.1 in long entry:\n%s", modStr1)
	}
	if !strings.Contains(modStr1, `- "80:80"`) {
		t.Errorf("short syntax entry altered when remediating long entry:\n%s", modStr1)
	}

	// 2. Remediate the short syntax entry on the modified file
	mod2, err := ModifyComposeBytes(mod1, "docker-compose.yml", "gateway", 6, 80, "127.0.0.1:80:80")
	if err != nil {
		t.Fatalf("ModifyComposeBytes on short entry failed: %v", err)
	}
	modStr2 := string(mod2)
	if !strings.Contains(modStr2, `- "127.0.0.1:80:80"`) {
		t.Errorf("expected remediated short syntax:\n%s", modStr2)
	}
	if !strings.Contains(modStr2, "host_ip: 127.0.0.1") {
		t.Errorf("long syntax entry altered when remediating short entry:\n%s", modStr2)
	}
}

func TestApplyComposeFix_LongForm_CreatesByteIdenticalBackup(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")

	initialContent := []byte(`services:
  web:
    image: nginx
    ports:
      - target: 80
        published: 8080
`)
	if err := os.WriteFile(composePath, initialContent, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	fp, err := ComputeFingerprint(composePath)
	if err != nil {
		t.Fatalf("ComputeFingerprint failed: %v", err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        5,
		Service:     "web",
		Before:      "published: 8080, target: 80",
		After:       "published: 8080, target: 80, host_ip: 127.0.0.1",
		Fingerprint: fp,
	}

	remediator := NewDefaultRemediator()
	res, err := remediator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected successful remediation, got error: %s", res.ErrorMessage)
	}

	// Verify backup existence and byte-identity to original content
	if res.BackupPath == "" {
		t.Fatalf("expected non-empty BackupPath in result")
	}
	backupData, err := os.ReadFile(res.BackupPath)
	if err != nil {
		t.Fatalf("failed to read backup file at %s: %v", res.BackupPath, err)
	}
	if !bytes.Equal(backupData, initialContent) {
		t.Errorf("backup bytes do not match initial content")
	}

	// Verify modified content on disk
	modifiedDisk, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read modified file: %v", err)
	}
	if !strings.Contains(string(modifiedDisk), "host_ip: 127.0.0.1") {
		t.Errorf("modified file on disk does not contain host_ip: 127.0.0.1:\n%s", string(modifiedDisk))
	}
}

func TestModifyComposeHostPortBytes_ShortSyntax(t *testing.T) {
	content := []byte(`services:
  web:
    image: nginx
    ports:
      - "8080:80" # web port
      - "127.0.0.1:9090:90"
      - "[::1]:7070:70/tcp"
`)

	// 1. Rewrite 8080:80 -> 8081:80
	mod1, err := ModifyComposeHostPortBytes(content, "compose.yaml", "web", 5, 8080, 8081)
	if err != nil {
		t.Fatalf("ModifyComposeHostPortBytes failed for 8080: %v", err)
	}
	if !strings.Contains(string(mod1), `"8081:80" # web port`) {
		t.Errorf("expected updated port with preserved comment, got:\n%s", string(mod1))
	}

	// 2. Rewrite 127.0.0.1:9090:90 -> 127.0.0.1:9091:90
	mod2, err := ModifyComposeHostPortBytes(mod1, "compose.yaml", "web", 6, 9090, 9091)
	if err != nil {
		t.Fatalf("ModifyComposeHostPortBytes failed for 9090: %v", err)
	}
	if !strings.Contains(string(mod2), `"127.0.0.1:9091:90"`) {
		t.Errorf("expected updated host IP binding, got:\n%s", string(mod2))
	}

	// 3. Rewrite [::1]:7070:70/tcp -> [::1]:7071:70/tcp
	mod3, err := ModifyComposeHostPortBytes(mod2, "compose.yaml", "web", 7, 7070, 7071)
	if err != nil {
		t.Fatalf("ModifyComposeHostPortBytes failed for 7070: %v", err)
	}
	if !strings.Contains(string(mod3), `"[::1]:7071:70/tcp"`) {
		t.Errorf("expected updated IPv6 binding, got:\n%s", string(mod3))
	}
}

func TestModifyComposeHostPortBytes_LongSyntax(t *testing.T) {
	content := []byte(`services:
  web:
    image: nginx
    ports:
      - target: 80
        published: 8080 # comment
        protocol: tcp
`)

	mod, err := ModifyComposeHostPortBytes(content, "compose.yaml", "web", 5, 8080, 8085)
	if err != nil {
		t.Fatalf("ModifyComposeHostPortBytes long syntax failed: %v", err)
	}
	if !strings.Contains(string(mod), "published: 8085 # comment") {
		t.Errorf("expected published: 8085 with preserved comment, got:\n%s", string(mod))
	}
}

func TestModifyComposeHostPortBytes_FailClosed_InterpolatedAndRange(t *testing.T) {
	contentInterpolated := []byte(`services:
  web:
    image: nginx
    ports:
      - "${PORT}:80"
`)
	_, err := ModifyComposeHostPortBytes(contentInterpolated, "compose.yaml", "web", 5, 0, 8081)
	if err == nil {
		t.Fatal("expected failure on variable interpolation, got nil")
	}
	if !strings.Contains(err.Error(), "variable interpolation") {
		t.Errorf("expected interpolation error message, got: %v", err)
	}

	contentRange := []byte(`services:
  web:
    image: nginx
    ports:
      - "8080-8085:80-85"
`)
	_, err = ModifyComposeHostPortBytes(contentRange, "compose.yaml", "web", 5, 8080, 8090)
	if err == nil {
		t.Fatal("expected failure on port range, got nil")
	}
	if !strings.Contains(err.Error(), "port ranges are not supported") {
		t.Errorf("expected port range error message, got: %v", err)
	}
}
