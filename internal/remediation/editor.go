package remediation

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"lantern/internal/compose"
)

// TargetLocation holds AST coordinates and text bounds for an exact Compose port item.
type TargetLocation struct {
	Service       string
	Line          int
	Value         string
	HostPort      uint16
	ContainerPort uint16
}

// FindTargetPort locates the exact Compose port item in the YAML AST.
// Refuses to proceed if the target is missing or ambiguous.
func FindTargetPort(data []byte, targetService string, targetLine int, targetPort uint16) (*TargetLocation, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid YAML syntax: %w", err)
	}

	docs := []*yaml.Node{&root}
	if root.Kind == yaml.DocumentNode {
		docs = root.Content
	}

	var matches []TargetLocation

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

		for i := 0; i < len(docMapping.Content)-1; i += 2 {
			keyNode := docMapping.Content[i]
			valNode := docMapping.Content[i+1]
			if keyNode.Value != "services" || valNode.Kind != yaml.MappingNode {
				continue
			}

			for j := 0; j < len(valNode.Content)-1; j += 2 {
				svcKey := valNode.Content[j]
				svcVal := valNode.Content[j+1]

				if targetService != "" && svcKey.Value != targetService {
					continue
				}

				if svcVal.Kind != yaml.MappingNode {
					continue
				}

				for p := 0; p < len(svcVal.Content)-1; p += 2 {
					portKey := svcVal.Content[p]
					portSeq := svcVal.Content[p+1]

					if portKey.Value != "ports" || portSeq.Kind != yaml.SequenceNode {
						continue
					}

					for _, item := range portSeq.Content {
						if item.Kind != yaml.ScalarNode {
							continue
						}

						// Match by line if targetLine provided
						if targetLine > 0 && item.Line != targetLine {
							continue
						}

						matches = append(matches, TargetLocation{
							Service: svcKey.Value,
							Line:    item.Line,
							Value:   item.Value,
						})
					}
				}
			}
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("target port declaration not found in Compose file for service %q (line %d)", targetService, targetLine)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous target port: found %d matching declarations in service %q", len(matches), targetService)
	}

	return &matches[0], nil
}

// ApplyComposeFix reads filePath, targets the exact Compose port declaration, modifies it
// to newEvidence, validates AST integrity, and returns the modified file bytes.
// Does NOT modify the file on disk.
func ApplyComposeFix(filePath string, targetService string, targetLine int, targetPort uint16, newEvidence string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Compose file: %w", err)
	}

	return ModifyComposeBytes(data, filePath, targetService, targetLine, targetPort, newEvidence)
}

// ModifyComposeBytes performs AST-targeted line replacement on raw Compose bytes and verifies invariants.
func ModifyComposeBytes(data []byte, filePath string, targetService string, targetLine int, targetPort uint16, newEvidence string) ([]byte, error) {
	// Parse initial evidence to establish baseline comparison
	initialEvidence, err := compose.ParseComposeFile(filePath, data)
	if err != nil {
		return nil, fmt.Errorf("cannot modify file with invalid initial Compose syntax: %w", err)
	}

	loc, err := FindTargetPort(data, targetService, targetLine, targetPort)
	if err != nil {
		return nil, err
	}

	hasCRLF := bytes.Contains(data, []byte("\r\n"))
	rawLines := strings.Split(string(data), "\n")

	if loc.Line < 1 || loc.Line > len(rawLines) {
		return nil, fmt.Errorf("target line %d is outside file line bounds (%d lines)", loc.Line, len(rawLines))
	}

	lineIdx := loc.Line - 1
	line := strings.TrimRight(rawLines[lineIdx], "\r")

	// Ensure line has sequence indicator '-'
	dashIdx := strings.Index(line, "-")
	if dashIdx == -1 {
		return nil, fmt.Errorf("line %d does not contain YAML sequence indicator '-': %q", loc.Line, line)
	}

	// Find the port token after '-'
	afterDash := line[dashIdx+1:]
	firstNonSpace := strings.IndexFunc(afterDash, func(r rune) bool {
		return r != ' ' && r != '\t'
	})
	if firstNonSpace == -1 {
		return nil, fmt.Errorf("line %d has no content after sequence indicator: %q", loc.Line, line)
	}

	valStartIdx := dashIdx + 1 + firstNonSpace

	// Find any trailing comment starting with '#'
	commentIdx := -1
	inQuote := false
	quoteChar := byte(0)
	for i := valStartIdx; i < len(line); i++ {
		ch := line[i]
		if !inQuote && (ch == '"' || ch == '\'') {
			inQuote = true
			quoteChar = ch
			continue
		}
		if inQuote && ch == quoteChar {
			inQuote = false
			quoteChar = 0
			continue
		}
		if !inQuote && ch == '#' {
			commentIdx = i
			break
		}
	}

	valEndIdx := len(line)
	suffix := ""
	if commentIdx != -1 {
		valEndIdx = commentIdx
		suffix = line[commentIdx:]
	}

	// Trim trailing whitespace from value portion
	valPortion := strings.TrimRight(line[valStartIdx:valEndIdx], " \t")
	spacingAfterVal := line[valStartIdx+len(valPortion) : valEndIdx]

	prefix := line[:valStartIdx]
	formattedReplacement := fmt.Sprintf("%q", newEvidence)

	newLine := prefix + formattedReplacement + spacingAfterVal + suffix
	rawLines[lineIdx] = newLine

	var joinSep string
	if hasCRLF {
		joinSep = "\r\n"
	} else {
		joinSep = "\n"
	}
	modifiedBytes := []byte(strings.Join(rawLines, joinSep))

	// Invariant Verification:
	// 1. Re-parse with yaml.Unmarshal to ensure strict YAML validity
	var verifyRoot yaml.Node
	if err := yaml.Unmarshal(modifiedBytes, &verifyRoot); err != nil {
		return nil, fmt.Errorf("modified content produced invalid YAML: %w", err)
	}

	// 2. Re-parse with compose.ParseComposeFile
	newEvidenceList, err := compose.ParseComposeFile(filePath, modifiedBytes)
	if err != nil {
		return nil, fmt.Errorf("modified content failed Compose validation: %w", err)
	}

	// 3. Confirm target port was updated to 127.0.0.1
	foundTargetUpdated := false
	for _, ne := range newEvidenceList {
		if ne.Service == loc.Service && ne.Line == loc.Line {
			cleanIP := strings.Trim(strings.TrimSpace(ne.Port.HostIP), "[]")
			if cleanIP == "127.0.0.1" {
				foundTargetUpdated = true
				break
			}
		}
	}
	if !foundTargetUpdated {
		return nil, fmt.Errorf("post-modification verification failed: target port on line %d was not updated to 127.0.0.1", loc.Line)
	}

	// 4. Confirm no other ports or services in the file were altered
	if len(newEvidenceList) != len(initialEvidence) {
		return nil, fmt.Errorf("post-modification verification failed: port declaration count changed from %d to %d", len(initialEvidence), len(newEvidenceList))
	}

	for i := range initialEvidence {
		orig := initialEvidence[i]
		mod := newEvidenceList[i]
		if orig.Line == loc.Line && orig.Service == loc.Service {
			continue // This was the target
		}
		if orig.Service != mod.Service || orig.Line != mod.Line || orig.Original != mod.Original {
			return nil, fmt.Errorf("unintended modification detected in service %q (line %d)", orig.Service, orig.Line)
		}
	}

	return modifiedBytes, nil
}
