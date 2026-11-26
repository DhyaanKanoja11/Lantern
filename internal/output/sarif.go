package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

const (
	sarifSchemaVersion = "2.1.0"
	sarifSchemaURI     = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	ruleWildcardID     = "LANTERN001"
)

// SarifFormatter serializes security exposure findings into OASIS SARIF v2.1.0 format
// for GitHub Code Scanning and Advanced Security consumption.
type SarifFormatter struct {
	toolVersion string
}

// NewSarifFormatter creates a new SarifFormatter with semantic version metadata.
func NewSarifFormatter(version string) *SarifFormatter {
	if version == "" {
		version = "0.4.0"
	}
	return &SarifFormatter{toolVersion: version}
}

// SarifReport represents the root of a SARIF v2.1.0 document.
type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun represents a single execution of the analysis tool.
type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

// SarifTool encapsulates information about the analysis tool driver.
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

// SarifDriver describes the analysis component.
type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"semanticVersion,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

// SarifRule defines a category of findings.
type SarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription SarifMultiformatString `json:"shortDescription"`
	FullDescription  SarifMultiformatString `json:"fullDescription,omitempty"`
	Help             *SarifHelp             `json:"help,omitempty"`
	DefaultConfig    SarifDefaultConfig     `json:"defaultConfiguration"`
}

// SarifMultiformatString holds a plain text message.
type SarifMultiformatString struct {
	Text string `json:"text"`
}

// SarifHelp contains remediation guidance.
type SarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SarifDefaultConfig specifies default severity level.
type SarifDefaultConfig struct {
	Level string `json:"level"`
}

// SarifResult represents an individual security finding.
type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations,omitempty"`
}

// SarifMessage represents a human-readable result message.
type SarifMessage struct {
	Text string `json:"text"`
}

// SarifLocation represents the physical or logical location of a finding.
type SarifLocation struct {
	PhysicalLocation *SarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SarifLogicalLocation `json:"logicalLocations,omitempty"`
}

// SarifPhysicalLocation points to a specific source file and line.
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

// SarifArtifactLocation points to a file path.
type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// SarifRegion specifies line or character numbers.
type SarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// SarifLogicalLocation describes an endpoint or process.
type SarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

func defaultSarifRules() []SarifRule {
	return []SarifRule{
		{
			ID:   ruleWildcardID,
			Name: "WildcardPortBinding",
			ShortDescription: SarifMultiformatString{
				Text: "Service bound to wildcard network address (0.0.0.0 or ::)",
			},
			FullDescription: SarifMultiformatString{
				Text: "The listening service is bound to a wildcard network address (0.0.0.0 or ::), making it accessible across all network interfaces including local Wi-Fi, Ethernet, and public internet.",
			},
			Help: &SarifHelp{
				Text:     "Change the port publication from 'PORT:PORT' to '127.0.0.1:PORT:PORT' in docker-compose.yml or your service configuration to restrict access to loopback.",
				Markdown: "Change the port publication from `PORT:PORT` to `127.0.0.1:PORT:PORT` in `docker-compose.yml` or your service configuration to restrict access to loopback.",
			},
			DefaultConfig: SarifDefaultConfig{
				Level: "error",
			},
		},
	}
}

// RenderScan formats scan results into SARIF v2.1.0 output.
func (s *SarifFormatter) RenderScan(w io.Writer, list []domain.ExposureSummary, notices ...string) error {
	var results []SarifResult

	for _, item := range list {
		if !isWildcard(item.Address) {
			continue
		}

		target := item.ProcessName
		if item.ContainerName != "" {
			target = fmt.Sprintf("%s (container: %s)", item.ProcessName, item.ContainerName)
		}

		msg := fmt.Sprintf("Port %d (%s) is bound to wildcard address %s with reachability %s",
			item.Port, target, item.Address, item.Reachability)

		res := SarifResult{
			RuleID:  ruleWildcardID,
			Level:   "error",
			Message: SarifMessage{Text: msg},
		}

		if item.ContainerName != "" {
			res.Locations = append(res.Locations, SarifLocation{
				LogicalLocations: []SarifLogicalLocation{
					{
						Name: item.ContainerName,
						Kind: "container",
					},
				},
			})
		} else if item.ProcessName != "" {
			res.Locations = append(res.Locations, SarifLocation{
				LogicalLocations: []SarifLogicalLocation{
					{
						Name: fmt.Sprintf("%s (PID %d)", item.ProcessName, item.PID),
						Kind: "process",
					},
				},
			})
		}

		results = append(results, res)
	}

	report := SarifReport{
		Schema:  sarifSchemaURI,
		Version: sarifSchemaVersion,
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "Lantern",
						Version:        s.toolVersion,
						InformationURI: "https://github.com/DhyaanKanoja11/Lantern",
						Rules:          defaultSarifRules(),
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderWhy formats an exposure causality into SARIF v2.1.0 output with file/line evidence.
func (s *SarifFormatter) RenderWhy(w io.Writer, exp *domain.Exposure) error {
	var results []SarifResult

	if exp != nil && isWildcard(exp.BindAddress) {
		reachStr := exp.Reachability.State
		if reachStr == "" {
			reachStr = "PUBLIC"
		}
		msg := fmt.Sprintf("Port %d is bound to wildcard address %s with reachability %s",
			exp.Port, exp.BindAddress, reachStr)

		res := SarifResult{
			RuleID:  ruleWildcardID,
			Level:   "error",
			Message: SarifMessage{Text: msg},
		}

		var loc SarifLocation
		if exp.Config != nil && exp.Config.File != "" {
			loc.PhysicalLocation = &SarifPhysicalLocation{
				ArtifactLocation: SarifArtifactLocation{
					URI: exp.Config.File,
				},
				Region: &SarifRegion{
					StartLine: exp.Config.Line,
				},
			}
		}

		if exp.Container != nil && exp.Container.Name != "" {
			loc.LogicalLocations = append(loc.LogicalLocations, SarifLogicalLocation{
				Name: exp.Container.Name,
				Kind: "container",
			})
		}

		if loc.PhysicalLocation != nil || len(loc.LogicalLocations) > 0 {
			res.Locations = append(res.Locations, loc)
		}

		results = append(results, res)
	}

	report := SarifReport{
		Schema:  sarifSchemaURI,
		Version: sarifSchemaVersion,
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "Lantern",
						Version:        s.toolVersion,
						InformationURI: "https://github.com/DhyaanKanoja11/Lantern",
						Rules:          defaultSarifRules(),
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func isWildcard(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "*" || addr == "[::]" || addr == "0:0:0:0:0:0:0:0"
}
