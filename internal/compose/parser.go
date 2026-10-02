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
