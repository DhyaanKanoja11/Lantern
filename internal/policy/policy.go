package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level .lantern.yaml schema.
type Config struct {
	Version int          `yaml:"version"`
	Policy  PolicyConfig `yaml:"policy"`
}

// PolicyConfig defines security rules for port exposures.
type PolicyConfig struct {
	FailOnWildcard bool  `yaml:"fail_on_wildcard"`
	IgnorePorts    []int `yaml:"ignore_ports"`
}

// LoadFile reads and parses a specific policy file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid policy file %s: %w", path, err)
	}
	return &cfg, nil
}

// FindAndLoad looks for .lantern.yaml or .lantern.yml in dir (or current directory if dir is empty).
// If no policy file exists, returns nil, "", nil without error.
func FindAndLoad(dir string) (*Config, string, error) {
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return nil, "", err
		}
	}

	candidates := []string{
		filepath.Join(dir, ".lantern.yaml"),
		filepath.Join(dir, ".lantern.yml"),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			cfg, err := LoadFile(path)
			if err != nil {
				return nil, path, err
			}
			return cfg, path, nil
		}
	}

	return nil, "", nil
}

// MergeWithFlags combines policy configuration with explicit CLI flags.
func (c *Config) MergeWithFlags(flagFailOnWildcard bool, flagFailChanged bool, flagIgnorePorts []int) (bool, []int) {
	effectiveFail := flagFailOnWildcard
	if !flagFailChanged && c != nil {
		effectiveFail = c.Policy.FailOnWildcard
	}

	seen := make(map[int]bool)
	var mergedPorts []int

	// Add policy ignore ports first
	if c != nil {
		for _, p := range c.Policy.IgnorePorts {
			if !seen[p] && p > 0 && p <= 65535 {
				seen[p] = true
				mergedPorts = append(mergedPorts, p)
			}
		}
	}

	// Add CLI flag ignore ports
	for _, p := range flagIgnorePorts {
		if !seen[p] && p > 0 && p <= 65535 {
			seen[p] = true
			mergedPorts = append(mergedPorts, p)
		}
	}

	return effectiveFail, mergedPorts
}
