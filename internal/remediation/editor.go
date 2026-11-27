package remediation

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/DhyaanKanoja11/Lantern/internal/compose"
	"gopkg.in/yaml.v3"
)

// TargetLocation holds AST coordinates and text bounds for an exact Compose port item.
type TargetLocation struct {
	Service       string
	Line          int
	Value         string
	HostPort      uint16
	ContainerPort uint16
	IsLongSyntax  bool
	MappingItem   *yaml.Node
	HostIPLine    int
	HostIPValue   string
	PublishedLine int
	LastItemLine  int
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
						if item.Kind == yaml.ScalarNode {
							// Match by line if targetLine provided
							if targetLine > 0 && item.Line != targetLine {
								continue
							}

							loc := TargetLocation{
								Service: svcKey.Value,
								Line:    item.Line,
								Value:   item.Value,
							}

							// If we know the host port, the declaration has to
							// actually publish it. Ephemeral ("80") and
							// unparseable values can't be checked here; later
							// verification handles those.
							if parsed, err := compose.ParsePortShort(item.Value); err == nil {
								if targetPort > 0 && !parsed.IsEphemeral() && !parsed.MatchesPort(targetPort) {
									continue
								}
								loc.HostPort = parsed.HostPortStart
								loc.ContainerPort = parsed.ContainerPort
								if targetPort > 0 && parsed.MatchesPort(targetPort) {
									loc.HostPort = targetPort
									// In "8080-8085:80-85", 8082 maps to 82.
									if parsed.ContainerPortEnd > parsed.ContainerPort {
										loc.ContainerPort = parsed.ContainerPort + (targetPort - parsed.HostPortStart)
									}
								}
							}

							matches = append(matches, loc)
						} else if item.Kind == yaml.MappingNode {
							var targetStr, publishedStr, protocolStr, hostIPStr string
							var targetValNode, publishedValNode, hostIPValNode *yaml.Node
							maxLine := item.Line

							for k := 0; k < len(item.Content)-1; k += 2 {
								keyNode := item.Content[k]
								valNode := item.Content[k+1]
								if keyNode.Line > maxLine {
									maxLine = keyNode.Line
								}
								if valNode.Line > maxLine {
									maxLine = valNode.Line
								}

								switch keyNode.Value {
								case "target":
									targetStr = valNode.Value
									targetValNode = valNode
								case "published":
									publishedStr = strings.TrimSpace(valNode.Value)
									publishedValNode = valNode
								case "protocol":
									protocolStr = strings.ToLower(strings.TrimSpace(valNode.Value))
								case "host_ip":
									hostIPStr = strings.Trim(strings.TrimSpace(valNode.Value), "[]")
									hostIPValNode = valNode
								}
							}

							// If targetLine specified, must match within mapping range
							if targetLine > 0 && (targetLine < item.Line || targetLine > maxLine) {
								continue
							}

							var containerPort uint16
							if targetValNode != nil {
								if cVal, err := strconv.ParseUint(targetStr, 10, 16); err == nil {
									containerPort = uint16(cVal)
								}
							}

							isInterp := strings.Contains(publishedStr, "${")
							isRange := strings.Contains(publishedStr, "-")

							if publishedValNode == nil || publishedStr == "" {
								// Ephemeral container port only
								if targetPort > 0 {
									continue
								}
							} else if !isInterp && !isRange {
								cleanPub := strings.Trim(publishedStr, "\"'")
								if pVal, err := strconv.ParseUint(cleanPub, 10, 16); err == nil {
									hostPort := uint16(pVal)
									if targetPort > 0 && hostPort != targetPort {
										continue
									}
								} else if targetPort > 0 {
									continue
								}
							} else if targetPort > 0 && targetLine == 0 {
								continue
							}

							_ = protocolStr
							loc := TargetLocation{
								Service:       svcKey.Value,
								Line:          item.Line,
								Value:         publishedStr,
								ContainerPort: containerPort,
								IsLongSyntax:  true,
								MappingItem:   item,
								HostIPLine:    0,
								HostIPValue:   hostIPStr,
								PublishedLine: 0,
								LastItemLine:  maxLine,
							}
							if publishedValNode != nil {
								loc.PublishedLine = publishedValNode.Line
								cleanPub := strings.Trim(publishedStr, "\"'")
								if pVal, err := strconv.ParseUint(cleanPub, 10, 16); err == nil {
									loc.HostPort = uint16(pVal)
								}
							}
							if hostIPValNode != nil {
								loc.HostIPLine = hostIPValNode.Line
							}

							matches = append(matches, loc)
						}
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

	for _, e := range initialEvidence {
		if e.Service == loc.Service && e.Line == loc.Line && e.Interpolated {
			return nil, fmt.Errorf("line %d uses variable interpolation (%s); refusing to replace it with a literal", loc.Line, e.Original)
		}
	}

	hasCRLF := bytes.Contains(data, []byte("\r\n"))
	rawLines := strings.Split(string(data), "\n")
	rawLinesOriginal := make([]string, len(rawLines))
	copy(rawLinesOriginal, rawLines)

	if loc.IsLongSyntax {
		if loc.Value == "" {
			return nil, fmt.Errorf("target long-form port declaration for service %q has no published host port", loc.Service)
		}
		if strings.Contains(loc.Value, "${") {
			return nil, fmt.Errorf("line %d uses variable interpolation (%s); refusing to replace it with a literal", loc.Line, loc.Value)
		}
		if strings.Contains(loc.Value, "-") {
			return nil, fmt.Errorf("port ranges are not supported for automatic remediation: service %q line %d", loc.Service, loc.Line)
		}

		if loc.HostIPLine > 0 {
			lineIdx := loc.HostIPLine - 1
			if lineIdx < 0 || lineIdx >= len(rawLines) {
				return nil, fmt.Errorf("target host_ip line %d is outside file bounds", loc.HostIPLine)
			}
			origLine := strings.TrimRight(rawLines[lineIdx], "\r")
			newLine, err := replaceHostIPInLine(origLine, "127.0.0.1")
			if err != nil {
				return nil, fmt.Errorf("failed to rewrite host_ip on line %d: %w", loc.HostIPLine, err)
			}
			rawLines[lineIdx] = newLine
		} else {
			indent := determineMappingIndentation(rawLines, loc.MappingItem)
			newLine := indent + "host_ip: 127.0.0.1"

			insertIdx := loc.LastItemLine
			if insertIdx < 0 || insertIdx > len(rawLines) {
				return nil, fmt.Errorf("target insert position %d is outside file bounds", insertIdx)
			}

			newLines := make([]string, 0, len(rawLines)+1)
			newLines = append(newLines, rawLines[:insertIdx]...)
			newLines = append(newLines, newLine)
			newLines = append(newLines, rawLines[insertIdx:]...)
			rawLines = newLines
		}
	} else {
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
	}

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

	// 3. Confirm the target now binds to 127.0.0.1 and that the host IP is
	// the *only* thing that changed. Ports, ranges and protocol must match
	// the original declaration exactly.
	var before, after *compose.ParsedPort
	for i := range initialEvidence {
		if initialEvidence[i].Service == loc.Service && initialEvidence[i].Line == loc.Line {
			before = &initialEvidence[i].Port
		}
	}
	for i := range newEvidenceList {
		if newEvidenceList[i].Service == loc.Service && newEvidenceList[i].Line == loc.Line {
			after = &newEvidenceList[i].Port
		}
	}
	if before == nil || after == nil {
		return nil, fmt.Errorf("post-modification verification failed: could not find target port on line %d", loc.Line)
	}
	if strings.Trim(strings.TrimSpace(after.HostIP), "[]") != "127.0.0.1" {
		return nil, fmt.Errorf("post-modification verification failed: target port on line %d was not updated to 127.0.0.1", loc.Line)
	}
	if before.HostPortStart != after.HostPortStart || before.HostPortEnd != after.HostPortEnd ||
		before.ContainerPort != after.ContainerPort || before.ContainerPortEnd != after.ContainerPortEnd ||
		before.Protocol != after.Protocol {
		return nil, fmt.Errorf("post-modification verification failed: %q -> %q changes more than the host IP", before.Original, after.Original)
	}

	// 4. Confirm no other ports or services in the file were altered
	if len(newEvidenceList) != len(initialEvidence) {
		return nil, fmt.Errorf("post-modification verification failed: port declaration count changed from %d to %d", len(initialEvidence), len(newEvidenceList))
	}

	lineShift := len(rawLines) - len(rawLinesOriginal)
	for i := range initialEvidence {
		orig := initialEvidence[i]
		mod := newEvidenceList[i]
		if orig.Line == loc.Line && orig.Service == loc.Service {
			continue // This was the target
		}
		expectedLine := orig.Line
		if orig.Line > loc.Line {
			expectedLine += lineShift
		}
		if orig.Service != mod.Service || mod.Line != expectedLine || orig.Original != mod.Original {
			return nil, fmt.Errorf("unintended modification detected in service %q (line %d)", orig.Service, orig.Line)
		}
	}

	return modifiedBytes, nil
}

func replaceHostIPInLine(line string, newIP string) (string, error) {
	keyIdx := strings.Index(line, "host_ip")
	if keyIdx == -1 {
		return "", fmt.Errorf("host_ip key not found in line: %q", line)
	}
	colonIdx := strings.Index(line[keyIdx:], ":")
	if colonIdx == -1 {
		return "", fmt.Errorf("colon not found after host_ip in line: %q", line)
	}
	actualColonIdx := keyIdx + colonIdx

	beforeColon := line[:actualColonIdx+1]
	rest := line[actualColonIdx+1:]

	nonSpaceIdx := strings.IndexFunc(rest, func(r rune) bool {
		return r != ' ' && r != '\t'
	})
	if nonSpaceIdx == -1 {
		return beforeColon + " " + newIP, nil
	}

	spacing := rest[:nonSpaceIdx]
	valAndAfter := rest[nonSpaceIdx:]

	quoteChar := byte(0)
	valEnd := len(valAndAfter)
	suffix := ""

	if valAndAfter[0] == '"' || valAndAfter[0] == '\'' {
		quoteChar = valAndAfter[0]
		closeQuoteIdx := strings.IndexByte(valAndAfter[1:], quoteChar)
		if closeQuoteIdx != -1 {
			valEnd = 1 + closeQuoteIdx + 1
			suffix = valAndAfter[valEnd:]
		}
	} else {
		commentIdx := strings.IndexByte(valAndAfter, '#')
		if commentIdx != -1 {
			valEnd = commentIdx
			suffix = valAndAfter[commentIdx:]
		}
		valStr := strings.TrimRight(valAndAfter[:valEnd], " \t")
		spacingAfterVal := valAndAfter[len(valStr):valEnd]
		suffix = spacingAfterVal + suffix
	}

	var formattedVal string
	if quoteChar != 0 {
		formattedVal = string(quoteChar) + newIP + string(quoteChar)
	} else {
		formattedVal = newIP
	}

	return beforeColon + spacing + formattedVal + suffix, nil
}

func determineMappingIndentation(rawLines []string, item *yaml.Node) string {
	if item != nil {
		for k := 0; k < len(item.Content)-1; k += 2 {
			keyNode := item.Content[k]
			lineIdx := keyNode.Line - 1
			if lineIdx >= 0 && lineIdx < len(rawLines) {
				lineText := strings.TrimRight(rawLines[lineIdx], "\r")
				trimmed := strings.TrimLeft(lineText, " \t")
				if !strings.HasPrefix(trimmed, "-") && len(trimmed) > 0 {
					return lineText[:len(lineText)-len(trimmed)]
				}
			}
		}
		if item.Line-1 >= 0 && item.Line-1 < len(rawLines) {
			lineText := strings.TrimRight(rawLines[item.Line-1], "\r")
			trimmed := strings.TrimLeft(lineText, " \t")
			prefix := lineText[:len(lineText)-len(trimmed)]
			return prefix + "  "
		}
	}
	return "        "
}

// ModifyComposeHostPortBytes rewrites the host/published port of an exact Compose port item
// to newHostPort. Supports both short syntax (e.g. "8080:80") and long syntax (published: 8080).
// Preserves comments, indentation, container port, host IP, and unrelated declarations.
// Fails closed if the port uses variable interpolation (${PORT}) or is a range.
func ModifyComposeHostPortBytes(data []byte, filePath string, targetService string, targetLine int, targetPort uint16, newHostPort uint16) ([]byte, error) {
	if newHostPort == 0 {
		return nil, fmt.Errorf("invalid new host port: %d", newHostPort)
	}

	initialEvidence, err := compose.ParseComposeFile(filePath, data)
	if err != nil {
		return nil, fmt.Errorf("cannot modify file with invalid initial Compose syntax: %w", err)
	}

	loc, err := FindTargetPort(data, targetService, targetLine, targetPort)
	if err != nil {
		return nil, err
	}

	for _, e := range initialEvidence {
		if e.Service == loc.Service && e.Line == loc.Line && e.Interpolated {
			return nil, fmt.Errorf("line %d uses variable interpolation (%s); refusing to replace it with a literal", loc.Line, e.Original)
		}
	}

	if loc.Value == "" {
		return nil, fmt.Errorf("target port declaration for service %q has no published host port", loc.Service)
	}
	if strings.Contains(loc.Value, "${") {
		return nil, fmt.Errorf("line %d uses variable interpolation (%s); refusing to replace it with a literal", loc.Line, loc.Value)
	}
	if strings.Contains(loc.Value, "-") {
		return nil, fmt.Errorf("port ranges are not supported for automatic remediation: service %q line %d", loc.Service, loc.Line)
	}

	hasCRLF := bytes.Contains(data, []byte("\r\n"))
	rawLines := strings.Split(string(data), "\n")

	if loc.IsLongSyntax {
		if loc.PublishedLine <= 0 || loc.PublishedLine > len(rawLines) {
			return nil, fmt.Errorf("published line %d is outside file line bounds (%d lines)", loc.PublishedLine, len(rawLines))
		}
		lineIdx := loc.PublishedLine - 1
		origLine := strings.TrimRight(rawLines[lineIdx], "\r")
		newLine, err := replacePublishedInLine(origLine, newHostPort)
		if err != nil {
			return nil, fmt.Errorf("failed to rewrite published port on line %d: %w", loc.PublishedLine, err)
		}
		rawLines[lineIdx] = newLine
	} else {
		if loc.Line < 1 || loc.Line > len(rawLines) {
			return nil, fmt.Errorf("target line %d is outside file line bounds (%d lines)", loc.Line, len(rawLines))
		}
		lineIdx := loc.Line - 1
		line := strings.TrimRight(rawLines[lineIdx], "\r")

		dashIdx := strings.Index(line, "-")
		if dashIdx == -1 {
			return nil, fmt.Errorf("line %d does not contain YAML sequence indicator '-': %q", loc.Line, line)
		}

		afterDash := line[dashIdx+1:]
		firstNonSpace := strings.IndexFunc(afterDash, func(r rune) bool {
			return r != ' ' && r != '\t'
		})
		if firstNonSpace == -1 {
			return nil, fmt.Errorf("line %d has no content after sequence indicator: %q", loc.Line, line)
		}

		valStartIdx := dashIdx + 1 + firstNonSpace

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

		rawVal := strings.TrimSpace(line[valStartIdx:valEndIdx])
		unquotedVal := rawVal
		if len(rawVal) >= 2 && ((rawVal[0] == '"' && rawVal[len(rawVal)-1] == '"') || (rawVal[0] == '\'' && rawVal[len(rawVal)-1] == '\'')) {
			unquotedVal = rawVal[1 : len(rawVal)-1]
		}

		rewrittenToken, err := rewriteShortHostPort(unquotedVal, newHostPort)
		if err != nil {
			return nil, fmt.Errorf("failed to rewrite short port on line %d: %w", loc.Line, err)
		}

		var formattedReplacement string
		if quoteChar != 0 || (len(rawVal) >= 2 && rawVal[0] == '"') {
			formattedReplacement = fmt.Sprintf("%q", rewrittenToken)
		} else if len(rawVal) >= 2 && rawVal[0] == '\'' {
			formattedReplacement = fmt.Sprintf("'%s'", rewrittenToken)
		} else {
			formattedReplacement = rewrittenToken
		}

		valPortion := strings.TrimRight(line[valStartIdx:valEndIdx], " \t")
		spacingAfterVal := line[valStartIdx+len(valPortion) : valEndIdx]
		prefix := line[:valStartIdx]

		newLine := prefix + formattedReplacement + spacingAfterVal + suffix
		rawLines[lineIdx] = newLine
	}

	var joinSep string
	if hasCRLF {
		joinSep = "\r\n"
	} else {
		joinSep = "\n"
	}
	modifiedBytes := []byte(strings.Join(rawLines, joinSep))

	// Invariant Verification:
	// 1. Strict YAML syntax
	var verifyRoot yaml.Node
	if err := yaml.Unmarshal(modifiedBytes, &verifyRoot); err != nil {
		return nil, fmt.Errorf("modified content produced invalid YAML: %w", err)
	}

	// 2. Compose validation
	newEvidenceList, err := compose.ParseComposeFile(filePath, modifiedBytes)
	if err != nil {
		return nil, fmt.Errorf("modified content failed Compose validation: %w", err)
	}

	// 3. Confirm target host port updated to newHostPort while keeping everything else identical
	var before, after *compose.ParsedPort
	for i := range initialEvidence {
		if initialEvidence[i].Service == loc.Service && initialEvidence[i].Line == loc.Line {
			before = &initialEvidence[i].Port
		}
	}
	for i := range newEvidenceList {
		if newEvidenceList[i].Service == loc.Service && newEvidenceList[i].Line == loc.Line {
			after = &newEvidenceList[i].Port
		}
	}
	if before == nil || after == nil {
		return nil, fmt.Errorf("post-modification verification failed: could not locate target port on line %d", loc.Line)
	}
	if after.HostPortStart != newHostPort {
		return nil, fmt.Errorf("post-modification verification failed: target port on line %d was not updated to %d (found %d)", loc.Line, newHostPort, after.HostPortStart)
	}
	if after.ContainerPort != before.ContainerPort {
		return nil, fmt.Errorf("post-modification verification failed: container port changed from %d to %d", before.ContainerPort, after.ContainerPort)
	}
	if !strings.EqualFold(after.Protocol, before.Protocol) {
		return nil, fmt.Errorf("post-modification verification failed: protocol changed from %s to %s", before.Protocol, after.Protocol)
	}
	if strings.Trim(strings.TrimSpace(after.HostIP), "[]") != strings.Trim(strings.TrimSpace(before.HostIP), "[]") {
		return nil, fmt.Errorf("post-modification verification failed: host IP changed from %s to %s", before.HostIP, after.HostIP)
	}

	return modifiedBytes, nil
}

func replacePublishedInLine(line string, newPort uint16) (string, error) {
	colonIdx := strings.Index(line, "published:")
	if colonIdx == -1 {
		return "", fmt.Errorf("line does not contain 'published:': %q", line)
	}

	beforeColon := line[:colonIdx+len("published:")]
	rest := line[colonIdx+len("published:"):]

	nonSpaceIdx := strings.IndexFunc(rest, func(r rune) bool {
		return r != ' ' && r != '\t'
	})
	if nonSpaceIdx == -1 {
		return "", fmt.Errorf("published declaration has no value: %q", line)
	}

	spacing := rest[:nonSpaceIdx]
	valAndAfter := rest[nonSpaceIdx:]

	quoteChar := byte(0)
	valEnd := len(valAndAfter)
	suffix := ""

	if valAndAfter[0] == '"' || valAndAfter[0] == '\'' {
		quoteChar = valAndAfter[0]
		closeQuoteIdx := strings.IndexByte(valAndAfter[1:], quoteChar)
		if closeQuoteIdx != -1 {
			valEnd = 1 + closeQuoteIdx + 1
			suffix = valAndAfter[valEnd:]
		}
	} else {
		commentIdx := strings.IndexByte(valAndAfter, '#')
		if commentIdx != -1 {
			valEnd = commentIdx
			suffix = valAndAfter[commentIdx:]
		}
		valStr := strings.TrimRight(valAndAfter[:valEnd], " \t")
		spacingAfterVal := valAndAfter[len(valStr):valEnd]
		suffix = spacingAfterVal + suffix
	}

	var formattedVal string
	if quoteChar != 0 {
		formattedVal = fmt.Sprintf("%c%d%c", quoteChar, newPort, quoteChar)
	} else {
		formattedVal = strconv.Itoa(int(newPort))
	}

	return beforeColon + spacing + formattedVal + suffix, nil
}

func rewriteShortHostPort(rawVal string, newPort uint16) (string, error) {
	protoSuffix := ""
	val := rawVal
	if idx := strings.LastIndex(val, "/"); idx != -1 {
		protoSuffix = val[idx:]
		val = val[:idx]
	}

	var hostIP string
	if strings.HasPrefix(val, "[") {
		closeIdx := strings.Index(val, "]")
		if closeIdx == -1 {
			return "", fmt.Errorf("unmatched ipv6 bracket in %q", rawVal)
		}
		hostIP = val[:closeIdx+1]
		val = strings.TrimPrefix(val[closeIdx+1:], ":")
	}

	if hostIP != "" {
		parts := strings.Split(val, ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("unexpected ipv6 port format in %q", rawVal)
		}
		return fmt.Sprintf("%s:%d:%s%s", hostIP, newPort, parts[1], protoSuffix), nil
	}

	parts := strings.Split(val, ":")
	switch len(parts) {
	case 2:
		// hostPort:containerPort
		return fmt.Sprintf("%d:%s%s", newPort, parts[1], protoSuffix), nil
	case 3:
		// hostIP:hostPort:containerPort
		return fmt.Sprintf("%s:%d:%s%s", parts[0], newPort, parts[2], protoSuffix), nil
	default:
		return "", fmt.Errorf("unsupported port mapping format for host port rewriting: %q", rawVal)
	}
}
