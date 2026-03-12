package rule

import (
	"testing"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

func TestSV6040_HelmManagedSecret(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantAny  bool
		wantNone bool
	}{
		{
			name: "Secret with Helm managed-by label",
			yaml: `apiVersion: v1
kind: Secret
metadata:
  name: myapp-creds
  labels:
    app.kubernetes.io/managed-by: Helm
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=`,
			wantAny: true,
		},
		{
			name: "Secret with Helm release annotation",
			yaml: `apiVersion: v1
kind: Secret
metadata:
  name: myapp-creds
  annotations:
    meta.helm.sh/release-name: myapp
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=`,
			wantAny: true,
		},
		{
			name: "Secret without Helm labels — no finding",
			yaml: `apiVersion: v1
kind: Secret
metadata:
  name: myapp-creds
  labels:
    app: myapp
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=`,
			wantNone: true,
		},
		{
			name: "managed-by not Helm — no finding",
			yaml: `apiVersion: v1
kind: Secret
metadata:
  name: myapp-creds
  labels:
    app.kubernetes.io/managed-by: ArgoCD
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=`,
			wantNone: true,
		},
		{
			name: "non-Secret resource — ignored",
			yaml: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  labels:
    app.kubernetes.io/managed-by: Helm
spec:
  replicas: 1`,
			wantNone: true,
		},
	}

	rule := NewHelmManagedSecretRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := k8s.ParseYAMLString(tt.yaml, "test.yaml")
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

			if tt.wantAny && len(findings) == 0 {
				t.Errorf("expected findings, got none")
			}
		})
	}
}
