package rule

import (
	"testing"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

func TestSV6020_KustomizeSecretGenEnv(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantIDs  []string
		wantNone bool
	}{
		{
			name: "secretGenerator with .env file",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: app-secrets
    envs:
      - .env`,
			wantIDs: []string{"SV6020"},
		},
		{
			name: "secretGenerator with .env.production",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: prod-secrets
    envs:
      - .env.production`,
			wantIDs: []string{"SV6020"},
		},
		{
			name: "secretGenerator with non-env file — no finding",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: app-secrets
    envs:
      - config.properties`,
			wantNone: true,
		},
		{
			name: "secretGenerator files pointing to secret file",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
secretGenerator:
  - name: tls
    files:
      - private_key=./server.key`,
			wantIDs: []string{"SV6020"},
		},
		{
			name: "no secretGenerator — no finding",
			yaml: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml`,
			wantNone: true,
		},
		{
			name: "non-Kustomization kind — ignored",
			yaml: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value`,
			wantNone: true,
		},
	}

	rule := NewKustomizeSecretGenEnvRule()
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
				t.Errorf("expected findings %v, got none", tt.wantIDs)
			}
		})
	}
}
