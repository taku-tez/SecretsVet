package output

import (
	"encoding/json"
	"io"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
	"github.com/SecretsVet/secretsvet/internal/version"
)

// JSONFormatter writes findings as a JSON document.
type JSONFormatter struct{}

type jsonFinding struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	File         string `json:"file"`
	Line         int    `json:"line,omitempty"`
	ResourceKind string `json:"resource_kind"`
	ResourceName string `json:"resource_name"`
	Namespace    string `json:"namespace,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type jsonSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type jsonOutput struct {
	Version  string        `json:"version"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

func (f *JSONFormatter) Write(w io.Writer, result *scanner.ScanResult) error {
	high, medium, low := result.Summary()
	out := jsonOutput{
		Version: version.Version(),
		Summary: jsonSummary{
			Total:  high + medium + low,
			High:   high,
			Medium: medium,
			Low:    low,
		},
	}
	for _, finding := range result.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			RuleID:       finding.RuleID,
			Severity:     string(finding.Severity),
			Message:      finding.Message,
			File:         finding.File,
			Line:         finding.Line,
			ResourceKind: finding.ResourceKind,
			ResourceName: finding.ResourceName,
			Namespace:    finding.Namespace,
			Detail:       finding.Detail,
		})
	}
	if out.Findings == nil {
		out.Findings = []jsonFinding{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Ensure rule package is imported for type safety in other files
var _ rule.Severity = rule.SeverityHigh

// jsonEncoder returns a configured JSON encoder for output writers.
func jsonEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc
}
