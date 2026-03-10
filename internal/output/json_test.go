package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
)

func TestJSONFormatterSeverityLowercase(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []rule.Finding{
			{RuleID: "SV4010", Severity: rule.SeverityCritical, Message: "etcd unencrypted", File: "cluster"},
			{RuleID: "SV1010", Severity: rule.SeverityHigh, Message: "aws key found", File: "deploy.yaml"},
			{RuleID: "SV1070", Severity: rule.SeverityMedium, Message: "not immutable", File: "secret.yaml"},
			{RuleID: "SV1050", Severity: rule.SeverityLow, Message: "envFrom configmap", File: "pod.yaml"},
		},
		Files:     2,
		Resources: 3,
	}

	var buf bytes.Buffer
	f := &JSONFormatter{}
	if err := f.Write(&buf, result); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var out struct {
		Summary struct {
			Total    int `json:"total"`
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		} `json:"summary"`
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify summary counts
	if out.Summary.Total != 4 {
		t.Errorf("summary.total = %d, want 4", out.Summary.Total)
	}
	if out.Summary.Critical != 1 {
		t.Errorf("summary.critical = %d, want 1", out.Summary.Critical)
	}
	if out.Summary.High != 1 {
		t.Errorf("summary.high = %d, want 1", out.Summary.High)
	}
	if out.Summary.Medium != 1 {
		t.Errorf("summary.medium = %d, want 1", out.Summary.Medium)
	}
	if out.Summary.Low != 1 {
		t.Errorf("summary.low = %d, want 1", out.Summary.Low)
	}

	// Verify all severity values are lowercase
	want := []string{"critical", "high", "medium", "low"}
	for i, f := range out.Findings {
		if f.Severity != want[i] {
			t.Errorf("findings[%d].severity = %q, want %q", i, f.Severity, want[i])
		}
	}
}

func TestGitJSONFormatterSeverityLowercase(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []rule.Finding{
			{RuleID: "SV3020", Severity: rule.SeverityCritical, Message: ".env committed"},
			{RuleID: "SV3040", Severity: rule.SeverityMedium, Message: "high entropy token"},
		},
	}

	var buf bytes.Buffer
	f := &JSONFormatter{}
	if err := f.Write(&buf, result); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var out struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, finding := range out.Findings {
		for _, ch := range finding.Severity {
			if ch >= 'A' && ch <= 'Z' {
				t.Errorf("severity %q contains uppercase characters", finding.Severity)
			}
		}
	}
}
