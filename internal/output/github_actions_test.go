package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
)

func TestGitHubActionsFormatter_Write(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []rule.Finding{
			{
				RuleID:   "SV1010",
				Severity: rule.SeverityHigh,
				Message:  "env[].value contains a secret pattern (aws-access-key-id)",
				File:     "k8s/deploy.yaml",
				Line:     42,
				Detail:   "env var: AWS_KEY",
			},
			{
				RuleID:   "SV1070",
				Severity: rule.SeverityLow,
				Message:  "Secret does not have immutable: true",
				File:     "k8s/secret.yaml",
				Line:     5,
			},
		},
		Files:     2,
		Resources: 3,
	}

	var buf bytes.Buffer
	f := &GitHubActionsFormatter{}
	if err := f.Write(&buf, result); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out := buf.String()

	// HIGH finding → ::error
	if !strings.Contains(out, "::error ") {
		t.Error("expected ::error for HIGH finding")
	}
	// LOW finding → ::warning
	if !strings.Contains(out, "::warning ") {
		t.Error("expected ::warning for LOW finding")
	}
	// File and line present
	if !strings.Contains(out, "file=k8s/deploy.yaml") {
		t.Error("expected file reference in output")
	}
	if !strings.Contains(out, "line=42") {
		t.Error("expected line number in output")
	}
	// Summary notice
	if !strings.Contains(out, "::notice") {
		t.Error("expected summary notice")
	}
}

func TestEscapeGHValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"foo:bar", "foo%3Abar"},
		{"a,b", "a%2Cb"},
		{"line\nnewline", "line%0Anewline"},
		{"percent%sign", "percent%25sign"},
	}
	for _, tt := range tests {
		got := escapeGHValue(tt.input)
		if got != tt.want {
			t.Errorf("escapeGHValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
