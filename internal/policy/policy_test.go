package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, ".lantern.yaml")
	content := `version: 1
policy:
  fail_on_wildcard: true
  ignore_ports:
    - 80
    - 443
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, err := LoadFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if !cfg.Policy.FailOnWildcard {
		t.Errorf("expected fail_on_wildcard true, got false")
	}
	if len(cfg.Policy.IgnorePorts) != 2 || cfg.Policy.IgnorePorts[0] != 80 || cfg.Policy.IgnorePorts[1] != 443 {
		t.Errorf("unexpected ignore_ports: %v", cfg.Policy.IgnorePorts)
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, ".lantern.yaml")
	if err := os.WriteFile(filePath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadFile(filePath)
	if err == nil {
		t.Fatal("expected error on invalid YAML, got nil")
	}
}

func TestFindAndLoad_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, path, err := FindAndLoad(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil || path != "" {
		t.Errorf("expected nil config and empty path, got cfg=%v path=%q", cfg, path)
	}
}

func TestFindAndLoad_DiscoversYml(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, ".lantern.yml")
	content := `version: 1
policy:
  fail_on_wildcard: true
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg, foundPath, err := FindAndLoad(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected discovered config, got nil")
	}
	if foundPath != filePath {
		t.Errorf("expected foundPath %q, got %q", filePath, foundPath)
	}
	if !cfg.Policy.FailOnWildcard {
		t.Errorf("expected fail_on_wildcard true")
	}
}

func TestConfig_MergeWithFlags(t *testing.T) {
	cfg := &Config{
		Version: 1,
		Policy: PolicyConfig{
			FailOnWildcard: true,
			IgnorePorts:    []int{80, 443},
		},
	}

	// 1. When flag is NOT explicitly changed by user, policy takes effect
	fail, ports := cfg.MergeWithFlags(false, false, []int{8080})
	if !fail {
		t.Errorf("expected policy fail_on_wildcard (true) to be preserved")
	}
	if len(ports) != 3 || ports[0] != 80 || ports[1] != 443 || ports[2] != 8080 {
		t.Errorf("expected merged ports [80, 443, 8080], got %v", ports)
	}

	// 2. When flag IS explicitly set to false by user, CLI flag overrides policy
	failOverride, _ := cfg.MergeWithFlags(false, true, nil)
	if failOverride {
		t.Errorf("expected explicit CLI flag (false) to override policy")
	}

	// 3. When cfg is nil (no file), CLI flags pass through cleanly
	var nilCfg *Config
	nilFail, nilPorts := nilCfg.MergeWithFlags(true, true, []int{3000})
	if !nilFail {
		t.Errorf("expected nilCfg to preserve flag value true")
	}
	if len(nilPorts) != 1 || nilPorts[0] != 3000 {
		t.Errorf("expected [3000], got %v", nilPorts)
	}
}
