package remediation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lantern/internal/domain"
)

// 1. Supported Compose wildcard exposure produces a remediation
func TestPlan_SupportedComposeWildcard(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  web:
    image: nginx
    ports:
      - "80:80"
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     5432,
			Protocol: "tcp",
			Address:  "0.0.0.0",
		},
		Container: &domain.Container{
			ID:   "c_pg",
			Name: "postgres",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          composePath,
			Line:          9,
			Evidence:      "5432:5432",
			Service:       "db",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       true,
		},
		Recommendation: &domain.Recommendation{
			Type:      "bind_localhost",
			Current:   "5432:5432",
			Suggested: "127.0.0.1:5432:5432",
		},
		Reachability: domain.Reachability{
			Local: true,
			LAN:   "yes",
			State: "LAN_REACHABLE",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationSupported {
		t.Fatalf("expected SUPPORTED, got %s (reason: %s)", plan.Status, plan.Reason)
	}
	if plan.File != composePath {
		t.Errorf("expected file %s, got %s", composePath, plan.File)
	}
	if plan.Line != 9 {
		t.Errorf("expected line 9, got %d", plan.Line)
	}
	if plan.Service != "db" {
		t.Errorf("expected service 'db', got %s", plan.Service)
	}
	if plan.Before != "5432:5432" {
		t.Errorf("expected Before '5432:5432', got %s", plan.Before)
	}
	if plan.After != "127.0.0.1:5432:5432" {
		t.Errorf("expected After '127.0.0.1:5432:5432', got %s", plan.After)
	}
}

// 2. Loopback Compose exposure produces no remediation (unsupported/already secure)
func TestPlan_LoopbackCompose(t *testing.T) {
	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "127.0.0.1",
		Listener: domain.Listener{
			Port:     5432,
			Protocol: "tcp",
			Address:  "127.0.0.1",
		},
		Container: &domain.Container{
			ID:   "c_pg",
			Name: "postgres",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "127.0.0.1",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          "/app/docker-compose.yml",
			Line:          9,
			HostIP:        "127.0.0.1",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       true,
		},
		Reachability: domain.Reachability{
			Local: true,
			LAN:   "no",
			State: "LOOPBACK_ONLY",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationUnsupported {
		t.Fatalf("expected UNSUPPORTED for loopback Compose, got %s", plan.Status)
	}
	if !strings.Contains(plan.Reason, "loopback") {
		t.Errorf("expected loopback mention in reason, got %s", plan.Reason)
	}
}

// 3. Uncertain root cause produces no automatic remediation
func TestPlan_UncertainRootCause(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	_ = os.WriteFile(composePath, []byte("services:\n  db:\n    ports:\n      - \"5432:5432\"\n"), 0644)

	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     5432,
			Protocol: "tcp",
			Address:  "0.0.0.0",
		},
		Container: &domain.Container{
			ID:   "c_pg",
			Name: "postgres",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          composePath,
			Line:          4,
			Evidence:      "5432:5432",
			Service:       "db",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       false, // Uncertain root cause!
		},
		Reachability: domain.Reachability{
			Local: true,
			LAN:   "yes",
			State: "LAN_REACHABLE",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationUnsafe {
		t.Fatalf("expected UNSAFE for uncertain root cause, got %s", plan.Status)
	}
	if !strings.Contains(plan.Reason, "uncertain") {
		t.Errorf("expected uncertainty reason, got: %s", plan.Reason)
	}
}

// 4. Unsupported native process produces no automatic remediation
func TestPlan_UnsupportedNativeProcess(t *testing.T) {
	exp := &domain.Exposure{
		Port:        3000,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     3000,
			Protocol: "tcp",
			Address:  "0.0.0.0",
		},
		Process: &domain.Process{
			PID:  1234,
			Name: "node",
		},
		Reachability: domain.Reachability{
			Local: true,
			LAN:   "yes",
			State: "LAN_REACHABLE",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationUnsupported {
		t.Fatalf("expected UNSUPPORTED for native process, got %s", plan.Status)
	}
	if !strings.Contains(plan.Reason, "native process") {
		t.Errorf("expected native process reason, got: %s", plan.Reason)
	}
}

// 5. Ambiguous evidence produces no remediation
func TestPlan_AmbiguousEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	// Two ports on the same service matching 5432 on different lines
	content := `services:
  db:
    ports:
      - "5432:5432"
      - "5432:5432"
`
	_ = os.WriteFile(composePath, []byte(content), 0644)

	exp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     5432,
			Protocol: "tcp",
			Address:  "0.0.0.0",
		},
		Container: &domain.Container{
			ID:   "c_pg",
			Name: "postgres",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          composePath,
			Line:          0, // Line unspecified -> ambiguous
			Service:       "db",
			HostPort:      5432,
			ContainerPort: 5432,
			Certain:       true,
		},
		Recommendation: &domain.Recommendation{
			Type:      "bind_localhost",
			Current:   "5432:5432",
			Suggested: "127.0.0.1:5432:5432",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationUnsafe {
		t.Fatalf("expected UNSAFE for ambiguous evidence, got %s", plan.Status)
	}
}

// 6. Exact target service/port is selected
func TestPlan_ExactTargetServiceAndPort(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	content := `services:
  api:
    image: api:v1
    ports:
      - "8080:8080"
  cache:
    image: redis:alpine
    ports:
      - "6379:6379"
`
	_ = os.WriteFile(composePath, []byte(content), 0644)

	exp := &domain.Exposure{
		Port:        6379,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     6379,
			Protocol: "tcp",
			Address:  "0.0.0.0",
		},
		Container: &domain.Container{
			ID:   "c_redis",
			Name: "cache",
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      6379,
			ContainerPort: 6379,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:          composePath,
			Line:          9,
			Evidence:      "6379:6379",
			Service:       "cache",
			HostPort:      6379,
			ContainerPort: 6379,
			Certain:       true,
		},
		Recommendation: &domain.Recommendation{
			Type:      "bind_localhost",
			Current:   "6379:6379",
			Suggested: "127.0.0.1:6379:6379",
		},
	}

	plan := Plan(exp)
	if plan.Status != domain.RemediationSupported {
		t.Fatalf("expected SUPPORTED, got %s (%s)", plan.Status, plan.Reason)
	}
	if plan.Service != "cache" || plan.Line != 9 {
		t.Errorf("expected service cache line 9, got %s line %d", plan.Service, plan.Line)
	}
}

// 7. Correct YAML declaration is modified
// 8. Unrelated services remain unchanged
// 9. Unrelated ports remain unchanged
// 10. Existing YAML structure and comments remain valid
func TestModifyComposeBytes_ExactAndUnchanged(t *testing.T) {
	initial := `version: '3.8'

services:
  web:
    image: nginx:alpine
    # primary web ingress
    ports:
      - "80:80" # public http
      - "443:443"

  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: secret
    ports:
      # db port for local dev
      - "5432:5432" # comment on port line
`
	res, err := ModifyComposeBytes([]byte(initial), "docker-compose.yml", "db", 17, 5432, "127.0.0.1:5432:5432")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resStr := string(res)

	// Target modified
	if !strings.Contains(resStr, `"127.0.0.1:5432:5432"`) {
		t.Errorf("expected modified port declaration, got:\n%s", resStr)
	}

	// Comment on target line preserved
	if !strings.Contains(resStr, `# comment on port line`) {
		t.Errorf("expected target line comment to be preserved, got:\n%s", resStr)
	}

	// Comment before target line preserved
	if !strings.Contains(resStr, `# db port for local dev`) {
		t.Errorf("expected db comment to be preserved, got:\n%s", resStr)
	}

	// Unrelated service web ports unchanged
	if !strings.Contains(resStr, `- "80:80" # public http`) {
		t.Errorf("expected web port 80 to remain completely unchanged, got:\n%s", resStr)
	}
	if !strings.Contains(resStr, `- "443:443"`) {
		t.Errorf("expected web port 443 to remain completely unchanged, got:\n%s", resStr)
	}

	// Environment variable unchanged
	if !strings.Contains(resStr, `POSTGRES_PASSWORD: secret`) {
		t.Errorf("expected environment variable to remain unchanged, got:\n%s", resStr)
	}
}

// 11. Existing backup is never silently overwritten
func TestCreateBackup_NeverOverwritesExistingBackup(t *testing.T) {
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "docker-compose.yml")
	origContent := []byte("original content")
	_ = os.WriteFile(origPath, origContent, 0644)

	// First backup
	bak1, err := CreateBackup(origPath)
	if err != nil {
		t.Fatalf("failed to create first backup: %v", err)
	}
	if bak1 != origPath+".lantern.bak" {
		t.Errorf("expected first backup name %s, got %s", origPath+".lantern.bak", bak1)
	}

	// Second backup should use a deterministic sequence and NOT overwrite bak1
	bak2, err := CreateBackup(origPath)
	if err != nil {
		t.Fatalf("failed to create second backup: %v", err)
	}
	if bak2 == bak1 {
		t.Errorf("second backup silently overwrote first backup %s", bak1)
	}
	if bak2 != origPath+".lantern.bak.1" {
		t.Errorf("expected second backup name %s.1, got %s", origPath+".lantern.bak", bak2)
	}

	// Confirm both backups exist
	if _, err := os.Stat(bak1); err != nil {
		t.Errorf("bak1 does not exist: %v", err)
	}
	if _, err := os.Stat(bak2); err != nil {
		t.Errorf("bak2 does not exist: %v", err)
	}
}

// 12. Backup matches original contents
func TestCreateBackup_MatchesOriginal(t *testing.T) {
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "compose.yaml")
	origContent := []byte("version: '3'\nservices:\n  redis:\n    ports:\n      - 6379:6379\n")
	_ = os.WriteFile(origPath, origContent, 0644)

	bakPath, err := CreateBackup(origPath)
	if err != nil {
		t.Fatalf("unexpected backup error: %v", err)
	}

	bakContent, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}

	if !bytes.Equal(origContent, bakContent) {
		t.Errorf("backup content mismatch:\nexpected: %s\ngot: %s", string(origContent), string(bakContent))
	}
}

// 13. Temporary write failure leaves original intact
// 14. Replacement failure does not produce a partial file
func TestAtomicWrite_Safety(t *testing.T) {
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "service.yml")
	origContent := []byte("untouched original content")
	_ = os.WriteFile(origPath, origContent, 0644)

	newContent := []byte("new replacement content")
	if err := AtomicWrite(origPath, newContent, 0644); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}

	readBack, _ := os.ReadFile(origPath)
	if !bytes.Equal(readBack, newContent) {
		t.Errorf("expected %s, got %s", string(newContent), string(readBack))
	}

	// Verify writing to non-existent directory fails safely without panic
	err := AtomicWrite(filepath.Join(tmpDir, "missing-dir", "file.yml"), []byte("data"), 0644)
	if err == nil {
		t.Fatal("expected error writing to non-existent directory")
	}
}

// 15. DefaultRemediator end-to-end Apply success and post-fix verification
func TestDefaultRemediator_Apply_Success(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	remediator := NewDefaultRemediator()
	fp, err := ComputeFingerprint(composePath)
	if err != nil {
		t.Fatal(err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        5,
		Service:     "db",
		Before:      "5432:5432",
		After:       "127.0.0.1:5432:5432",
		Reason:      "Docker Compose publishes host port to all network interfaces.",
		Fingerprint: fp,
	}

	res, err := remediator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("unexpected error applying fix: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected success, got error: %s", res.ErrorMessage)
	}

	// Confirm original file on disk now contains localhost binding
	content, _ := os.ReadFile(composePath)
	if !strings.Contains(string(content), `"127.0.0.1:5432:5432"`) {
		t.Errorf("file on disk was not updated:\n%s", string(content))
	}

	// Confirm backup file exists
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Errorf("backup file does not exist: %v", err)
	}
}

// 16. DefaultRemediator fails safely on invalid status
func TestDefaultRemediator_Apply_InvalidStatus(t *testing.T) {
	remediator := NewDefaultRemediator()
	plan := &domain.Remediation{
		Status: domain.RemediationUnsupported,
		Reason: "not supported",
	}

	_, err := remediator.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("expected error applying unsupported plan, got nil")
	}
}

// 17. TOCTOU: Apply rejected when file modified after plan creation
func TestDefaultRemediator_Apply_TOCTOU_ModifiedFile(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := "services:\n  db:\n    ports:\n      - \"5432:5432\"\n"
	_ = os.WriteFile(composePath, []byte(composeContent), 0644)

	remediator := NewDefaultRemediator()
	fp, err := ComputeFingerprint(composePath)
	if err != nil {
		t.Fatal(err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        4,
		Service:     "db",
		Before:      "5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	// External modification occurs after plan was created
	modifiedContent := "services:\n  db:\n    ports:\n      - \"5432:5432\"\n    restart: always\n"
	_ = os.WriteFile(composePath, []byte(modifiedContent), 0644)

	_, err = remediator.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("expected apply to be rejected on modified file, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged, got: %v", err)
	}

	// Verify modified file was NOT touched by Lantern
	onDisk, _ := os.ReadFile(composePath)
	if string(onDisk) != modifiedContent {
		t.Errorf("expected modified file to remain untouched, got:\n%s", string(onDisk))
	}

	// Verify no backup was created
	bakPath := composePath + ".lantern.bak"
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Errorf("expected no backup to be created on TOCTOU failure")
	}
}

// 18. TOCTOU: Apply rejected when file modified with exact same byte length
func TestDefaultRemediator_Apply_TOCTOU_SameSizeModifiedFile(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	// Both are exactly 45 bytes
	c1 := "services:\n  db:\n    ports:\n      - \"5432:5432\"\n"
	c2 := "services:\n  db:\n    ports:\n      - \"5433:5433\"\n"
	_ = os.WriteFile(composePath, []byte(c1), 0644)

	remediator := NewDefaultRemediator()
	fp, err := ComputeFingerprint(composePath)
	if err != nil {
		t.Fatal(err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        4,
		Service:     "db",
		Before:      "5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	// Replace with same-size different content
	_ = os.WriteFile(composePath, []byte(c2), 0644)

	_, err = remediator.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("expected apply to be rejected on same-size modified file, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged, got: %v", err)
	}

	// Verify file was NOT touched
	onDisk, _ := os.ReadFile(composePath)
	if string(onDisk) != c2 {
		t.Errorf("expected file to remain untouched, got:\n%s", string(onDisk))
	}
}

// 19. TOCTOU: Apply rejected when file was deleted
func TestDefaultRemediator_Apply_TOCTOU_DeletedFile(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	_ = os.WriteFile(composePath, []byte("services:\n  db:\n    ports:\n      - 5432:5432\n"), 0644)

	remediator := NewDefaultRemediator()
	fp, err := ComputeFingerprint(composePath)
	if err != nil {
		t.Fatal(err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        4,
		Service:     "db",
		Before:      "5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	// Delete file before apply
	_ = os.Remove(composePath)

	_, err = remediator.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("expected apply to be rejected on deleted file, got nil")
	}
	if !errors.Is(err, ErrFileChanged) {
		t.Errorf("expected ErrFileChanged, got: %v", err)
	}
}

// 20. Apply rejected if plan has no recorded fingerprint
func TestDefaultRemediator_Apply_MissingFingerprint(t *testing.T) {
	remediator := NewDefaultRemediator()
	plan := &domain.Remediation{
		Status: domain.RemediationSupported,
		File:   "some-path",
	}

	_, err := remediator.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("expected error applying plan with missing fingerprint, got nil")
	}
}
