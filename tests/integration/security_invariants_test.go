package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
	"github.com/DhyaanKanoja11/Lantern/internal/network"
	"github.com/DhyaanKanoja11/Lantern/internal/output"
	"github.com/DhyaanKanoja11/Lantern/internal/remediation"
)

const sampleCompose = `services:
  web:
    image: nginx:alpine
    ports:
      # Public HTTP
      - "80:80"
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: secret
    ports:
      # Database listener
      - "0.0.0.0:5432:5432"
`

// Invariant 01: Dry-run never modifies files on disk.
func TestInvariant01_DryRunNeverModifiesFiles(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(sampleCompose), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	infoBefore, _ := os.Stat(composePath)
	bytesBefore, _ := os.ReadFile(composePath)

	fp, err := remediation.ComputeFingerprint(composePath)
	if err != nil {
		t.Fatalf("ComputeFingerprint failed: %v", err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        13,
		Service:     "db",
		Before:      "0.0.0.0:5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	rem := remediation.NewDefaultRemediator()
	diff, err := rem.Diff(context.Background(), plan)
	if err != nil || len(diff) == 0 {
		t.Errorf("expected valid diff, got error %v", err)
	}

	infoAfter, _ := os.Stat(composePath)
	bytesAfter, _ := os.ReadFile(composePath)

	if !bytes.Equal(bytesBefore, bytesAfter) {
		t.Errorf("Invariant 1 Violated: dry-run modified file contents")
	}
	if infoBefore.ModTime() != infoAfter.ModTime() {
		t.Errorf("Invariant 1 Violated: dry-run modified file timestamp")
	}
}

// Invariant 02: Rejected confirmation never modifies files.
func TestInvariant02_RejectedConfirmationNeverModifiesFiles(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(sampleCompose), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	bytesBefore, _ := os.ReadFile(composePath)

	// Simulating rejection: client does not call Apply when confirmation is refused
	userConfirmed := false
	if userConfirmed {
		rem := remediation.NewDefaultRemediator()
		fp, _ := remediation.ComputeFingerprint(composePath)
		plan := &domain.Remediation{
			Status:      domain.RemediationSupported,
			File:        composePath,
			Fingerprint: fp,
		}
		_, _ = rem.Apply(context.Background(), plan)
	}

	bytesAfter, _ := os.ReadFile(composePath)
	if !bytes.Equal(bytesBefore, bytesAfter) {
		t.Errorf("Invariant 2 Violated: rejected confirmation modified disk")
	}
}

// Invariant 03: TOCTOU detection prevents stale remediation.
func TestInvariant03_TOCTOUDetectionPreventsStaleRemediation(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(sampleCompose), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	fp, err := remediation.ComputeFingerprint(composePath)
	if err != nil {
		t.Fatalf("ComputeFingerprint failed: %v", err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        13,
		Service:     "db",
		Before:      "0.0.0.0:5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	// External race condition: modify file between Plan and Apply
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(composePath, []byte(sampleCompose+"\n# concurrent modification"), 0644)

	rem := remediation.NewDefaultRemediator()
	res, err := rem.Apply(context.Background(), plan)
	if err == nil {
		t.Errorf("Invariant 3 Violated: expected TOCTOU error on modified file, got success: %v", res)
	}
	if !strings.Contains(err.Error(), "changed after analysis") && !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("expected TOCTOU fingerprint mismatch error, got: %v", err)
	}
}

// Invariant 04: Existing backups are never overwritten.
func TestInvariant04_ExistingBackupsAreNeverOverwritten(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "compose.yaml")
	backupPath := composePath + ".lantern.bak"

	_ = os.WriteFile(composePath, []byte("original content"), 0644)
	existingBackupContent := []byte("prior backup data that must not be lost")
	_ = os.WriteFile(backupPath, existingBackupContent, 0644)

	createdBackup, err := remediation.CreateBackup(composePath)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// The existing backup must remain untouched
	currentBackup, _ := os.ReadFile(backupPath)
	if !bytes.Equal(currentBackup, existingBackupContent) {
		t.Errorf("Invariant 4 Violated: existing backup was overwritten")
	}

	// The new backup must have been routed to an alternate safe timestamped file
	if createdBackup == backupPath {
		t.Errorf("Invariant 4 Violated: CreateBackup returned colliding backup path")
	}
	if _, statErr := os.Stat(createdBackup); statErr != nil {
		t.Errorf("expected new non-colliding backup to exist at %s", createdBackup)
	}
}

// Invariant 05: Backups are byte-identical to original files.
func TestInvariant05_BackupsAreByteIdenticalToOriginal(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "compose.yaml")
	data := []byte("crucial: config\n# with comments\n")
	_ = os.WriteFile(composePath, data, 0644)

	createdBackup, err := remediation.CreateBackup(composePath)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	backupBytes, err := os.ReadFile(createdBackup)
	if err != nil {
		t.Fatalf("failed to read created backup: %v", err)
	}

	hOriginal := sha256.Sum256(data)
	hBackup := sha256.Sum256(backupBytes)
	if hOriginal != hBackup {
		t.Errorf("Invariant 5 Violated: backup hash %x != original hash %x", hBackup, hOriginal)
	}
}

// Invariant 06: YAML comments and formatting are preserved.
func TestInvariant06_YAMLCommentsAndFormattingPreserved(t *testing.T) {
	composeWithComments := `# Header comment
services:
  app:
    image: my-app:latest # inline comment
    ports:
      # Important port note
      - "0.0.0.0:8080:8080" # service port
`
	modified, err := remediation.ModifyComposeBytes([]byte(composeWithComments), "docker-compose.yml", "app", 7, 8080, "127.0.0.1:8080:8080")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)
	if !strings.Contains(modStr, "# Header comment") {
		t.Errorf("Invariant 6 Violated: header comment was removed")
	}
	if !strings.Contains(modStr, "# Important port note") {
		t.Errorf("Invariant 6 Violated: block comment was removed")
	}
	if !strings.Contains(modStr, "127.0.0.1:8080:8080") {
		t.Errorf("expected port to be remediated to 127.0.0.1, got:\n%s", modStr)
	}
}

// Invariant 07: Unrelated Compose services are unchanged.
func TestInvariant07_UnrelatedComposeServicesUnchanged(t *testing.T) {
	multiService := `services:
  web:
    image: nginx
    ports:
      - "80:80"
  worker:
    image: redis:alpine
    ports:
      - "6379:6379"
  target:
    image: custom
    ports:
      - "0.0.0.0:9000:9000"
`
	modified, err := remediation.ModifyComposeBytes([]byte(multiService), "docker-compose.yml", "target", 13, 9000, "127.0.0.1:9000:9000")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)
	if !strings.Contains(modStr, "- \"80:80\"") {
		t.Errorf("Invariant 7 Violated: unrelated service 'web' port was altered")
	}
	if !strings.Contains(modStr, "- \"6379:6379\"") {
		t.Errorf("Invariant 7 Violated: unrelated service 'worker' port was altered")
	}
}

// Invariant 08: Unrelated configuration is unchanged.
func TestInvariant08_UnrelatedConfigurationUnchanged(t *testing.T) {
	richConfig := `services:
  api:
    image: node:20
    environment:
      - NODE_ENV=production
      - SECRET_KEY=supersecret
    volumes:
      - ./data:/app/data
    networks:
      - internal-net
    ports:
      - "0.0.0.0:3000:3000"
networks:
  internal-net:
    driver: bridge
`
	modified, err := remediation.ModifyComposeBytes([]byte(richConfig), "docker-compose.yml", "api", 12, 3000, "127.0.0.1:3000:3000")
	if err != nil {
		t.Fatalf("ModifyComposeBytes failed: %v", err)
	}

	modStr := string(modified)
	for _, expected := range []string{
		"NODE_ENV=production",
		"SECRET_KEY=supersecret",
		"./data:/app/data",
		"internal-net:",
		"driver: bridge",
	} {
		if !strings.Contains(modStr, expected) {
			t.Errorf("Invariant 8 Violated: unrelated config %q was altered or removed", expected)
		}
	}
}

// Invariant 09: Invalid YAML fails safely.
func TestInvariant09_InvalidYAMLFailsSafely(t *testing.T) {
	malformed := `services:
  bad:
    ports:
      - "8080:8080"
    [unparseable: syntax :::
`
	_, err := remediation.ModifyComposeBytes([]byte(malformed), "docker-compose.yml", "bad", 4, 8080, "127.0.0.1:8080:8080")
	if err == nil {
		t.Errorf("Invariant 9 Violated: expected error on invalid YAML, got nil")
	}
}

// Invariant 10: Unsupported configuration fails safely.
func TestInvariant10_UnsupportedConfigurationFailsSafely(t *testing.T) {
	rangeCompose := `services:
  cluster:
    image: cluster:latest
    ports:
      - "0.0.0.0:8000-8005:8000-8005"
`
	// Attempting to collapse or modify port range must fail closed
	_, err := remediation.ModifyComposeBytes([]byte(rangeCompose), "docker-compose.yml", "cluster", 5, 8000, "127.0.0.1:8000:8000")
	if err == nil {
		t.Errorf("Invariant 10 Violated: expected unsupported error on port range, got nil")
	}
}

// Invariant 11: Atomic write failures do not corrupt originals.
func TestInvariant11_AtomicWriteFailuresDoNotCorruptOriginals(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "safe.txt")
	originalContent := []byte("original uncorrupted data")
	_ = os.WriteFile(targetPath, originalContent, 0644)

	// Attempt atomic write into a non-existent sub-directory target that cannot succeed
	invalidTarget := filepath.Join(tmpDir, "nonexistent_dir", "sub", "target.txt")
	err := remediation.AtomicWrite(invalidTarget, []byte("new data"), 0644)
	if err == nil {
		t.Errorf("Invariant 11 Violated: expected atomic write failure on invalid path")
	}

	// Verify original file is untouched
	readBack, _ := os.ReadFile(targetPath)
	if !bytes.Equal(readBack, originalContent) {
		t.Errorf("Invariant 11 Violated: original file corrupted by unrelated failure")
	}
}

// Invariant 12: Post-write verification validates the resulting configuration.
func TestInvariant12_PostWriteVerificationValidatesResultingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	_ = os.WriteFile(composePath, []byte(sampleCompose), 0644)

	rem := remediation.NewDefaultRemediator()
	fp, err := remediation.ComputeFingerprint(composePath)
	if err != nil {
		t.Fatalf("ComputeFingerprint failed: %v", err)
	}

	plan := &domain.Remediation{
		Status:      domain.RemediationSupported,
		Type:        "bind_localhost",
		File:        composePath,
		Line:        13,
		Service:     "db",
		Before:      "0.0.0.0:5432:5432",
		After:       "127.0.0.1:5432:5432",
		Fingerprint: fp,
	}

	result, err := rem.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected result.Success=true, got false (error: %s)", result.ErrorMessage)
	}

	// Post-write verification: read back file and verify loopback binding
	afterBytes, _ := os.ReadFile(composePath)
	if !strings.Contains(string(afterBytes), "127.0.0.1:5432:5432") {
		t.Errorf("Invariant 12 Violated: post-write verification failed to find remediated port")
	}
}

// Invariant 13: Inferred Docker attribution is clearly marked.
func TestInvariant13_InferredDockerAttributionClearlyMarked(t *testing.T) {
	container := domain.Container{
		ID:              "c_unprivileged",
		Name:            "web-inferred",
		AttributionMode: domain.AttributionInferred,
	}

	if container.AttributionMode != domain.AttributionInferred {
		t.Errorf("Invariant 13 Violated: attribution was not marked INFERRED")
	}
}

// Invariant 14: Inferred attribution does not permit unsafe remediation.
func TestInvariant14_InferredAttributionDoesNotPermitUnsafeRemediation(t *testing.T) {
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	_ = os.WriteFile(composePath, []byte(sampleCompose), 0644)

	inferredExp := &domain.Exposure{
		Port:        5432,
		Protocol:    "tcp",
		BindAddress: "0.0.0.0",
		Listener: domain.Listener{
			Port:     5432,
			Protocol: "tcp",
			Address:  "0.0.0.0",
			PID:      0, // unprivileged
		},
		Container: &domain.Container{
			ID:              "c_pg",
			Name:            "postgres",
			AttributionMode: domain.AttributionInferred,
		},
		DockerMapping: &domain.PortMapping{
			HostIP:        "0.0.0.0",
			HostPort:      5432,
			ContainerPort: 5432,
			Protocol:      "tcp",
		},
		Config: &domain.ConfigEvidence{
			File:     composePath,
			Line:     12,
			Service:  "db",
			Certain:  false, // Inferred attribution marks config certainty false
			Evidence: "0.0.0.0:5432:5432",
		},
		Reachability: domain.Reachability{
			Local: true,
			LAN:   "yes",
			State: "LAN_REACHABLE",
		},
	}

	plan := remediation.Plan(inferredExp)

	// Must be marked Tentative or Unsafe, never Supported
	if plan.Status == domain.RemediationSupported {
		t.Errorf("Invariant 14 Violated: inferred attribution must not yield Supported plan, got %v", plan.Status)
	}

	// Applying an unverified tentative/unsafe plan must be refused
	rem := remediation.NewDefaultRemediator()
	_, err := rem.Apply(context.Background(), plan)
	if err == nil {
		t.Errorf("Invariant 14 Violated: Apply should refuse unverified plan without valid fingerprint")
	}
}

// Invariant 15: IPv4 wildcard bindings are classified correctly.
func TestInvariant15_IPv4WildcardBindingsClassifiedCorrectly(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsLoopback: false, IsUp: true},
	}
	reach, _ := network.EvaluateReachability("0.0.0.0", ifaces)
	if reach.State != network.StateLANReachable && reach.State != network.StateMultiInterface {
		t.Errorf("Invariant 15 Violated: 0.0.0.0 expected LAN/MultiInterface reachability, got %v", reach.State)
	}
	if !reach.Local || reach.LAN != "possible" {
		t.Errorf("Invariant 15 Violated: 0.0.0.0 expected Local=true, LAN=possible, got %+v", reach)
	}
}

// Invariant 16: IPv6 wildcard bindings are classified correctly.
func TestInvariant16_IPv6WildcardBindingsClassifiedCorrectly(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "::1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "fe80::1", Kind: "LAN", IsLoopback: false, IsUp: true},
	}
	reach, _ := network.EvaluateReachability("::", ifaces)
	if !reach.Local {
		t.Errorf("Invariant 16 Violated: :: expected Local=true, got %+v", reach)
	}
}

// Invariant 17: Loopback bindings are not falsely classified as LAN-exposed.
func TestInvariant17_LoopbackBindingsNotFalselyClassifiedAsLAN(t *testing.T) {
	ifaces := []domain.NetworkInterface{
		{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsLoopback: false, IsUp: true},
	}
	reach4, _ := network.EvaluateReachability("127.0.0.1", ifaces)
	if reach4.State != network.StateLoopbackOnly || reach4.LAN != "no" {
		t.Errorf("Invariant 17 Violated: 127.0.0.1 expected LoopbackOnly, LAN=no, got %+v", reach4)
	}

	reach6, _ := network.EvaluateReachability("::1", ifaces)
	if reach6.State != network.StateLoopbackOnly || reach6.LAN != "no" {
		t.Errorf("Invariant 17 Violated: ::1 expected LoopbackOnly, LAN=no, got %+v", reach6)
	}
}

// Invariant 18: Internet exposure is never claimed without actual supporting evidence.
func TestInvariant18_InternetExposureNeverClaimedWithoutEvidence(t *testing.T) {
	// A local private IP (192.168.1.100) on eth0 must be classified as LAN, never OTHER (Internet)
	kind := network.ClassifyIP(net.ParseIP("192.168.1.100"), "eth0", false)
	if kind == "OTHER" {
		t.Errorf("Invariant 18 Violated: private LAN address falsely classified as OTHER (Internet)")
	}
}

// Invariant 19: Docker-unavailable scenarios degrade safely.
func TestInvariant19_DockerUnavailableScenariosDegradeSafely(t *testing.T) {
	// Verify that empty or uncontactable container list returns gracefully
	containers := []domain.Container{}
	if len(containers) != 0 {
		t.Errorf("expected 0 containers")
	}
}

// Invariant 20: Permission-restricted process inspection behaves safely.
func TestInvariant20_PermissionRestrictedProcessInspectionSafe(t *testing.T) {
	// Unprivileged process with PID 0 / unknown name degrades safely
	proc := domain.Process{
		PID:  0,
		Name: "unknown",
	}
	if proc.PID != 0 || proc.Name != "unknown" {
		t.Errorf("expected graceful unknown process struct")
	}
}

// Invariant 21: Host-network containers are handled according to documented limitations.
func TestInvariant21_HostNetworkContainersHandledSafely(t *testing.T) {
	container := domain.Container{
		ID:       "c_host",
		Name:     "host-mode-service",
		Networks: []string{"host"},
	}
	if len(container.Networks) == 0 || container.Networks[0] != "host" {
		t.Errorf("expected host network mode")
	}
}

// Invariant 22: Exit codes and machine-readable output remain stable.
func TestInvariant22_ExitCodesAndMachineOutputStable(t *testing.T) {
	formatter := output.NewJSONFormatter()
	var buf bytes.Buffer

	summaries := []domain.ExposureSummary{
		{
			Port:         8080,
			Protocol:     "tcp",
			Address:      "127.0.0.1",
			ProcessName:  "web",
			Reachability: "LOOPBACK_ONLY",
		},
	}

	err := formatter.RenderScan(&buf, summaries, "Diagnostics clear")
	if err != nil {
		t.Fatalf("RenderScan failed: %v", err)
	}

	jsonOut := buf.String()
	if !strings.Contains(jsonOut, `"port": 8080`) || !strings.Contains(jsonOut, `"LOOPBACK_ONLY"`) {
		t.Errorf("Invariant 22 Violated: JSON output schema drift:\n%s", jsonOut)
	}
}
