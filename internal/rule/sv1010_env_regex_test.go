package rule

import (
	"strings"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

func mustLoadYAML(t *testing.T, content string) *k8s.Resource {
	t.Helper()
	resources, err := k8s.ParseYAMLString(content, "test.yaml")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(resources) == 0 {
		t.Fatal("no resources parsed")
	}
	return resources[0]
}

func TestEnvRegexRule(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: AWS_KEY
              value: AKIAIOSFODNN7EXAMPLE
            - name: NORMAL
              value: hello-world
            - name: FROM_SECRET
              valueFrom:
                secretKeyRef:
                  name: mysecret
                  key: key
`
	res := mustLoadYAML(t, yaml)
	findings := NewEnvRegexRule().Check(res)

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Message)
		}
	}
	if len(findings) > 0 {
		f := findings[0]
		if f.RuleID != "SV1010" {
			t.Errorf("expected SV1010, got %s", f.RuleID)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("expected HIGH severity, got %s", f.Severity)
		}
		if !strings.Contains(f.Detail, "AWS_KEY") {
			t.Errorf("expected detail to mention AWS_KEY, got: %s", f.Detail)
		}
	}
}

func TestEnvRegexRule_NoFindings(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clean-deploy
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: db-secret
                  key: url
`
	res := mustLoadYAML(t, yaml)
	findings := NewEnvRegexRule().Check(res)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean deployment, got %d", len(findings))
	}
}
