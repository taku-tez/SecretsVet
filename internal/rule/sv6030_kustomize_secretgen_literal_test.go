package rule

import (
	"testing"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

func TestSV6030_KustomizeSecretGenLiteral(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHigh bool
		wantAny  bool
		wantNone bool
	}{
		{
			name: "literal with Stripe API key pattern",
			// key assembled at runtime so the literal doesn't appear in source
			yaml: "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n" +
				"secretGenerator:\n  - name: app-secrets\n    literals:\n" +
				"      - API_KEY=" + "sk_" + "live_51AbcDEFghIJklMNopQRsTUvwxYZ012345",
			wantHigh: true,
		},
		{
			name: "literal with suspicious key and plaintext value",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: db-secrets
    literals:
      - DB_PASSWORD=supersecretpassword123`,
			wantAny: true,
		},
		{
			name: "literal with non-suspicious key and short value — no finding",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: app-config
    literals:
      - APP_PORT=8080`,
			wantNone: true,
		},
		{
			name: "literal with empty value — no finding",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: app-secrets
    literals:
      - API_KEY=`,
			wantNone: true,
		},
		{
			name: "no literals — no finding",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: app-secrets
    envs:
      - .env`,
			wantNone: true,
		},
	}

	rule := NewKustomizeSecretGenLiteralRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := k8s.ParseYAMLString(tt.yaml, "kustomization.yaml")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			var findings []Finding
			for _, res := range resources {
				findings = append(findings, rule.Check(res)...)
			}

			if tt.wantNone {
				if len(findings) > 0 {
					t.Errorf("expected no findings, got %d: %+v", len(findings), findings)
				}
				return
			}

			if len(findings) == 0 {
				t.Errorf("expected findings, got none")
				return
			}

			if tt.wantHigh {
				found := false
				for _, f := range findings {
					if f.Severity == SeverityHigh {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected HIGH severity finding, got: %+v", findings)
				}
			}
		})
	}
}
