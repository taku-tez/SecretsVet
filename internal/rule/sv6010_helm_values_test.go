package rule

import (
	"testing"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

func TestSV6010_HelmValues(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		yaml     string
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "AWS key in values.yaml",
			file: "values.yaml",
			yaml: `aws:
  accessKeyId: AKIAIOSFODNN7EXAMPLE`,
			wantIDs: []string{"SV6010"},
		},
		{
			name: "suspicious key with plaintext password in values.yaml",
			file: "values.yaml",
			yaml: `database:
  password: supersecretpassword123`,
			wantIDs: []string{"SV6010"},
		},
		{
			name: "nested values-staging.yaml",
			file: "values-staging.yaml",
			// key assembled at runtime so the literal doesn't appear in source
			yaml: "stripe:\n  apiKey: " + "sk_" + "live_51AbcDEFghIJklMNopQ",
			wantIDs: []string{"SV6010"},
		},
		{
			name: "placeholder value — no finding",
			file: "values.yaml",
			yaml: `database:
  password: changeme`,
			wantNone: true,
		},
		{
			name: "empty value — no finding",
			file: "values.yaml",
			yaml: `github:
  token: ""`,
			wantNone: true,
		},
		{
			name: "non-helm YAML file — not scanned by SV6010",
			file: "deployment.yaml",
			yaml: `database:
  password: supersecretpassword123`,
			wantNone: true,
		},
		{
			name: "numeric value — no finding",
			file: "values.yaml",
			yaml: `app:
  port: 8080`,
			wantNone: true,
		},
	}

	rule := NewHelmValuesRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := k8s.ParseYAMLString(tt.yaml, tt.file)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			var findings []Finding
			for _, res := range resources {
				findings = append(findings, rule.Check(res)...)
			}

			if tt.wantNone {
				if len(findings) > 0 {
					t.Errorf("expected no findings, got %d: %v", len(findings), findings)
				}
				return
			}

			if len(findings) == 0 {
				t.Errorf("expected findings %v, got none", tt.wantIDs)
				return
			}

			for _, id := range tt.wantIDs {
				found := false
				for _, f := range findings {
					if f.RuleID == id {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding with RuleID=%s, not found in %v", id, findings)
				}
			}
		})
	}
}

func TestIsHelmValuesFile(t *testing.T) {
	hits := []string{"values.yaml", "values.yml", "values-prod.yaml", "values-staging.yml", "values_dev.yaml"}
	misses := []string{"deployment.yaml", "kustomization.yaml", "Chart.yaml", "values-extra.json"}

	for _, name := range hits {
		if !isHelmValuesFile(name) {
			t.Errorf("isHelmValuesFile(%q) = false, want true", name)
		}
	}
	for _, name := range misses {
		if isHelmValuesFile(name) {
			t.Errorf("isHelmValuesFile(%q) = true, want false", name)
		}
	}
}
