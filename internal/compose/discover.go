package compose

import (
	"os"
	"path/filepath"
	"strings"

	"lantern/internal/domain"
)

// FileReader abstracts filesystem access for reading Compose files.
type FileReader interface {
	ReadFile(name string) ([]byte, error)
	Stat(name string) (os.FileInfo, error)
}

type osFileReader struct{}

func (osFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (osFileReader) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// DiscoverConfigFiles locates Compose configuration files associated with a container.
// Priority:
// 1. Explicit `com.docker.compose.project.config_files` label.
// 2. Predictable filenames in `com.docker.compose.project.working_dir` or fallback directory.
// Never scans arbitrary or parent directories recursively.
func DiscoverConfigFiles(container *domain.Container, reader FileReader, fallbackBaseDir string) ([]string, string, error) {
	if reader == nil {
		reader = osFileReader{}
	}

	var workingDir string
	var configFilesStr string
	var hasLabels bool

	if container != nil && len(container.Labels) > 0 {
		hasLabels = true
		workingDir = strings.TrimSpace(container.Labels["com.docker.compose.project.working_dir"])
		configFilesStr = strings.TrimSpace(container.Labels["com.docker.compose.project.config_files"])
	}

	if workingDir == "" {
		workingDir = fallbackBaseDir
	}

	// 1. Explicit config_files label
	if configFilesStr != "" {
		rawFiles := strings.Split(configFilesStr, ",")
		var discovered []string
		for _, f := range rawFiles {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}

			var candidate string
			if filepath.IsAbs(f) {
				candidate = filepath.Clean(f)
			} else if workingDir != "" {
				candidate = filepath.Clean(filepath.Join(workingDir, f))
			} else {
				candidate = filepath.Clean(f)
			}

			if fi, err := reader.Stat(candidate); err == nil && !fi.IsDir() {
				discovered = append(discovered, candidate)
			}
		}

		if len(discovered) == 0 {
			return nil, workingDir, ErrComposeFileNotFound
		}
		return discovered, workingDir, nil
	}

	// 2. Conservative fallback search for predictable filenames in workingDir (or fallbackBaseDir)
	searchDir := workingDir
	if searchDir == "" {
		searchDir = "."
	}

	predictable := []string{
		"compose.yaml",
		"compose.yml",
		"docker-compose.yaml",
		"docker-compose.yml",
	}

	var discovered []string
	for _, name := range predictable {
		candidate := filepath.Clean(filepath.Join(searchDir, name))
		if fi, err := reader.Stat(candidate); err == nil && !fi.IsDir() {
			discovered = append(discovered, candidate)
			break // pick first matching predictable file
		}
	}

	if len(discovered) > 0 {
		return discovered, searchDir, nil
	}

	if !hasLabels {
		return nil, searchDir, ErrComposeMetadataUnavailable
	}

	return nil, searchDir, ErrComposeFileNotFound
}
