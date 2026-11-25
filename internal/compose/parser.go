package compose

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ExtractedEvidence represents a port declaration extracted directly from Compose YAML AST.
type ExtractedEvidence struct {
	File     string
	Line     int
	Service  string
	Port     ParsedPort
	Original string

	// Interpolated is set when the declaration uses ${VAR} / $VAR. Port
	// then holds the value resolved from the environment and .env, which
	// may not be what the running container was started with.
	Interpolated bool
	// Unresolved is set when an interpolated declaration couldn't be
	// resolved (variable unset, no default). Port is empty in that case.
	Unresolved bool
}

// ParseComposeFile parses a Compose YAML file into ExtractedEvidence slice using yaml.Node AST.
// Preserves exact 1-indexed source line numbers from AST nodes.
func ParseComposeFile(filePath string, data []byte) ([]ExtractedEvidence, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}

	var results []ExtractedEvidence
	lookup := envLookup(filePath)

	// A YAML file can contain one or multiple documents
	docs := []*yaml.Node{&root}
	if root.Kind == yaml.DocumentNode {
		docs = root.Content
	}

	for _, doc := range docs {
		if doc == nil || len(doc.Content) == 0 {
			continue
		}

		docMapping := doc
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			docMapping = doc.Content[0]
		}

		if docMapping.Kind != yaml.MappingNode {
			continue
		}

		// Search for top-level "services" key
		for i := 0; i < len(docMapping.Content)-1; i += 2 {
			keyNode := docMapping.Content[i]
			valNode := docMapping.Content[i+1]

			if keyNode.Value != "services" || valNode.Kind != yaml.MappingNode {
				continue
			}

			// Iterate over services
			for j := 0; j < len(valNode.Content)-1; j += 2 {
				svcKeyNode := valNode.Content[j]
				svcValNode := valNode.Content[j+1]

				serviceName := svcKeyNode.Value
				if svcValNode.Kind != yaml.MappingNode {
					continue
				}

				// Search for "ports" within service
				for p := 0; p < len(svcValNode.Content)-1; p += 2 {
					portKeyNode := svcValNode.Content[p]
					portValNode := svcValNode.Content[p+1]

					if portKeyNode.Value != "ports" || portValNode.Kind != yaml.SequenceNode {
						continue
					}

					for _, itemNode := range portValNode.Content {
						line := itemNode.Line

						switch itemNode.Kind {
						case yaml.ScalarNode:
							if hasInterpolation(itemNode.Value) {
								results = append(results, interpolatedShort(filePath, line, serviceName, itemNode.Value, lookup))
								continue
							}
							parsed, err := parsePortShort(itemNode.Value)
							if err != nil {
								// Skip malformed port declaration safely without crashing
								continue
							}
							results = append(results, ExtractedEvidence{
								File:     filePath,
								Line:     line,
								Service:  serviceName,
								Port:     *parsed,
								Original: parsed.Original,
							})

						case yaml.MappingNode:
							if ev, ok := interpolatedLong(filePath, line, serviceName, itemNode, lookup); ok {
								results = append(results, ev)
								continue
							}
							parsed, err := parsePortLong(itemNode)
							if err != nil {
								// Skip malformed long syntax safely
								continue
							}
							results = append(results, ExtractedEvidence{
								File:     filePath,
								Line:     line,
								Service:  serviceName,
								Port:     *parsed,
								Original: parsed.Original,
							})
						}
					}
				}
			}
		}
	}

	return results, nil
}

// interpolatedShort turns a short-syntax declaration containing variables
// into evidence. It is always reported, even when it can't be resolved, so
// callers can tell the user why a port didn't match instead of dropping it.
func interpolatedShort(file string, line int, service, raw string, lookup lookupFunc) ExtractedEvidence {
	ev := ExtractedEvidence{
		File:         file,
		Line:         line,
		Service:      service,
		Original:     raw,
		Interpolated: true,
		Unresolved:   true,
		Port:         ParsedPort{Original: raw},
	}
	resolved, ok := interpolate(raw, lookup)
	if !ok {
		return ev
	}
	parsed, err := parsePortShort(resolved)
	if err != nil {
		return ev
	}
	parsed.Original = raw
	ev.Port = *parsed
	ev.Unresolved = false
	return ev
}

// interpolatedLong does the same for long syntax. ok is false when the
// mapping has no variables and should go through the normal path.
func interpolatedLong(file string, line int, service string, node *yaml.Node, lookup lookupFunc) (ExtractedEvidence, bool) {
	uses := false
	for _, c := range node.Content {
		if c.Kind == yaml.ScalarNode && hasInterpolation(c.Value) {
			uses = true
		}
	}
	if !uses {
		return ExtractedEvidence{}, false
	}

	ev := ExtractedEvidence{
		File:         file,
		Line:         line,
		Service:      service,
		Interpolated: true,
		Unresolved:   true,
	}

	copyNode := *node
	copyNode.Content = make([]*yaml.Node, len(node.Content))
	resolvedAll := true
	for i, c := range node.Content {
		cc := *c
		if cc.Kind == yaml.ScalarNode && hasInterpolation(cc.Value) {
			v, ok := interpolate(cc.Value, lookup)
			if !ok {
				resolvedAll = false
			}
			cc.Value = v
		}
		copyNode.Content[i] = &cc
	}
	if resolvedAll {
		if parsed, err := parsePortLong(&copyNode); err == nil {
			ev.Port = *parsed
			ev.Unresolved = false
		}
	}
	ev.Original = ev.Port.Original
	return ev, true
}
