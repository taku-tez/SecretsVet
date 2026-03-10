package rule

import (
	"testing"
)

func TestParseDurationHours(t *testing.T) {
	tests := []struct {
		input     string
		wantHours float64
		wantErr   bool
	}{
		{"1h", 1, false},
		{"24h", 24, false},
		{"72h", 72, false},
		{"48h30m", 48.5, false},
		{"1d", 24, false},
		{"2d", 48, false},
		{"30m", 0.5, false},
		{"3600s", 1, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseDurationHours(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDurationHours(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDurationHours(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.wantHours {
			t.Errorf("parseDurationHours(%q) = %.2f, want %.2f", tt.input, got, tt.wantHours)
		}
	}
}

func TestRefreshIntervalRule(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		wantFindings int
	}{
		{
			name: "over 24h triggers finding",
			yaml: `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: test
spec:
  refreshInterval: 72h
  secretStoreRef:
    name: store
    kind: SecretStore
  target:
    name: test
`,
			wantFindings: 1,
		},
		{
			name: "exactly 24h is OK",
			yaml: `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: test
spec:
  refreshInterval: 24h
  secretStoreRef:
    name: store
    kind: SecretStore
  target:
    name: test
`,
			wantFindings: 0,
		},
		{
			name: "1h is OK",
			yaml: `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: test
spec:
  refreshInterval: 1h
`,
			wantFindings: 0,
		},
	}

	rule := NewRefreshIntervalRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustLoadYAML(t, tt.yaml)
			findings := rule.Check(res)
			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for _, f := range findings {
					t.Logf("  %s: %s", f.RuleID, f.Message)
				}
			}
		})
	}
}
