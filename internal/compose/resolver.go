package compose

import (
	"context"
	"fmt"
	"strings"

	"lantern/internal/domain"
)

// Resolver attributes host port exposure to Docker Compose configuration files.
type Resolver struct {
	reader  FileReader
	baseDir string
}

// Compile-time interface assertion
var (
	_ ComposeResolver  = (*Resolver)(nil)
	_ ComposeInspector = (*Resolver)(nil)
)

// NewDefaultResolver creates a Resolver using OS filesystem access.
func NewDefaultResolver() *Resolver {
	return NewResolverWithReader(osFileReader{}, "")
}

// NewResolverWithReader creates a Resolver with custom FileReader and fallback directory.
func NewResolverWithReader(reader FileReader, baseDir string) *Resolver {
	if reader == nil {
		reader = osFileReader{}
	}
	return &Resolver{
		reader:  reader,
		baseDir: baseDir,
	}
}

// SetBaseDir sets the fallback directory for Compose discovery.
func (r *Resolver) SetBaseDir(baseDir string) {
	r.baseDir = baseDir
}

// FindPortEvidence discovers all matching Compose port declarations for a container and port.
func (r *Resolver) FindPortEvidence(
	ctx context.Context,
	container *domain.Container,
	hostAddress string,
	hostPort uint16,
) ([]domain.ConfigEvidence, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files, _, err := DiscoverConfigFiles(container, r.reader, r.baseDir)
	if err != nil {
		return nil, err
	}

	var targetService string
	if container != nil && len(container.Labels) > 0 {
		targetService = strings.TrimSpace(container.Labels["com.docker.compose.service"])
	}

	var matched []ExtractedEvidence
	readSuccessCount := 0

	for _, file := range files {
		data, errRead := r.reader.ReadFile(file)
		if errRead != nil {
			continue
		}
		readSuccessCount++

		declarations, errParse := ParseComposeFile(file, data)
		if errParse != nil {
			return nil, errParse
		}

		for _, decl := range declarations {
			// 1. Service matching
			if targetService != "" && !strings.EqualFold(decl.Service, targetService) {
				continue
			}

			// 2. Port matching
			if decl.Port.IsEphemeral() {
				if !decl.Port.MatchesContainerPort(hostPort, container) {
					continue
				}
			} else {
				if !decl.Port.MatchesPort(hostPort) {
					continue
				}
			}

			// 3. Address matching
			if !decl.Port.MatchesAddress(hostAddress) {
				continue
			}

			// 4. Protocol matching
			if container != nil && len(container.Ports) > 0 {
				protoMatch := true
				for _, m := range container.Ports {
					if m.HostPort == hostPort && m.Protocol != "" {
						if !decl.Port.MatchesProtocol(m.Protocol) {
							protoMatch = false
						}
						break
					}
				}
				if !protoMatch {
					continue
				}
			}

			matched = append(matched, decl)
		}
	}

	if readSuccessCount == 0 && len(files) > 0 {
		return nil, ErrComposeFileUnreadable
	}

	if len(matched) == 0 {
		return nil, ErrNoMatchingPort
	}

	// Exact certainty only when service was identified deterministically and uniquely
	isCertain := (targetService != "" && len(matched) == 1)

	var results []domain.ConfigEvidence
	for _, m := range matched {
		results = append(results, domain.ConfigEvidence{
			File:          m.File,
			Line:          m.Line,
			Service:       m.Service,
			Kind:          "compose",
			Certain:       isCertain,
			HostIP:        m.Port.HostIP,
			HostPort:      hostPort,
			ContainerPort: m.Port.ContainerPort,
			Protocol:      m.Port.Protocol,
			Original:      m.Original,
			Evidence:      fmt.Sprintf("%s: %s", m.Service, m.Original),
		})
	}

	return results, nil
}

// ResolveAttribution satisfies the ComposeResolver interface, returning unique evidence or error if ambiguous.
func (r *Resolver) ResolveAttribution(ctx context.Context, container *domain.Container, hostPort uint16) (*domain.ConfigEvidence, error) {
	// Look up Docker container port mappings for hostPort to retrieve HostIP
	var candidateIP string
	var conflictingIPs bool
	if container != nil {
		for _, m := range container.Ports {
			if m.HostPort == hostPort {
				cleanIP := strings.Trim(strings.TrimSpace(m.HostIP), "[]")
				if cleanIP != "" {
					if candidateIP == "" {
						candidateIP = cleanIP
					} else if !strings.EqualFold(candidateIP, cleanIP) {
						conflictingIPs = true
					}
				}
			}
		}
	}

	// Preserve ambiguity if Docker metadata contains multiple conflicting HostIPs for this hostPort
	if conflictingIPs {
		return nil, ErrAmbiguousAttribution
	}

	evidences, err := r.FindPortEvidence(ctx, container, candidateIP, hostPort)
	if err != nil {
		return nil, err
	}

	if len(evidences) == 0 {
		return nil, ErrNoMatchingPort
	}

	if len(evidences) > 1 {
		return nil, ErrAmbiguousAttribution
	}

	return &evidences[0], nil
}
