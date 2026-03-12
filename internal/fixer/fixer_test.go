package fixer

import (
	"strings"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/rule"
)

// ── StaticFix coverage ────────────────────────────────────────────────────────

// rulesWithStaticFix lists all rule IDs that have a static fix template.
var rulesWithStaticFix = []string{
	"SV1010", "SV1020", "SV1030", "SV1040", "SV1050",
	"SV1060", "SV1070",
	"SV2030", "SV2040", "SV2080", "SV2100",
	"SV3010",
	"SV4030", "SV4040",
	"SV6010", "SV6020", "SV6030", "SV6040",
}

func TestStaticFix_AllRulesHaveTemplates(t *testing.T) {
	for _, id := range rulesWithStaticFix {
		f := rule.Finding{
			RuleID:       id,
			Severity:     rule.SeverityHigh,
			Message:      "test finding",
			File:         "test.yaml",
			ResourceKind: "Deployment",
			ResourceName: "myapp",
			Namespace:    "default",
		}
		fix := StaticFix(f, "en")
		if fix == nil {
			t.Errorf("StaticFix(%s) returned nil — missing template", id)
			continue
		}
		if fix.RuleID != id {
			t.Errorf("StaticFix(%s).RuleID = %q, want %q", id, fix.RuleID, id)
		}
		if fix.Problem == "" {
			t.Errorf("StaticFix(%s).Problem is empty", id)
		}
		if fix.Solution == "" {
			t.Errorf("StaticFix(%s).Solution is empty", id)
		}
		if fix.Source != "static" {
			t.Errorf("StaticFix(%s).Source = %q, want static", id, fix.Source)
		}
	}
}

func TestStaticFix_JapaneseTranslations(t *testing.T) {
	for _, id := range rulesWithStaticFix {
		f := rule.Finding{RuleID: id, Severity: rule.SeverityHigh}
		en := StaticFix(f, "en")
		ja := StaticFix(f, "ja")
		if en == nil || ja == nil {
			continue
		}
		if en.Problem == ja.Problem {
			t.Errorf("StaticFix(%s): Japanese and English Problem are identical — translation missing?", id)
		}
	}
}

func TestStaticFix_UnknownRule(t *testing.T) {
	f := rule.Finding{RuleID: "SV9999", Severity: rule.SeverityLow}
	fix := StaticFix(f, "en")
	if fix != nil {
		t.Error("StaticFix(SV9999) should return nil for unknown rule")
	}
}

func TestStaticFix_SV1010_EnvNameExtraction(t *testing.T) {
	f := rule.Finding{
		RuleID:    "SV1010",
		Severity:  rule.SeverityHigh,
		Detail:    "env var: MY_API_KEY, value: sk_...",
		Namespace: "default",
	}
	fix := StaticFix(f, "en")
	if fix == nil {
		t.Fatal("StaticFix(SV1010) returned nil")
	}
	// Should include the env var name in the YAML snippet
	if !strings.Contains(fix.YAMLSnippet, "MY_API_KEY") {
		t.Errorf("SV1010 fix YAML should reference env var name MY_API_KEY, got:\n%s", fix.YAMLSnippet)
	}
}

func TestStaticFix_SV1070_SecretName(t *testing.T) {
	f := rule.Finding{
		RuleID:       "SV1070",
		Severity:     rule.SeverityLow,
		ResourceName: "my-database-secret",
		Namespace:    "production",
	}
	fix := StaticFix(f, "en")
	if fix == nil {
		t.Fatal("StaticFix(SV1070) returned nil")
	}
	if !strings.Contains(fix.YAMLSnippet, "my-database-secret") {
		t.Errorf("SV1070 fix YAML should reference resource name, got:\n%s", fix.YAMLSnippet)
	}
}

func TestStaticFix_SV6040_ResourceName(t *testing.T) {
	f := rule.Finding{
		RuleID:       "SV6040",
		Severity:     rule.SeverityMedium,
		ResourceName: "myapp-creds",
		Namespace:    "staging",
	}
	fix := StaticFix(f, "en")
	if fix == nil {
		t.Fatal("StaticFix(SV6040) returned nil")
	}
	if !strings.Contains(fix.YAMLSnippet, "myapp-creds") {
		t.Errorf("SV6040 fix YAML should reference resource name, got:\n%s", fix.YAMLSnippet)
	}
}

// ── parseLLMResponse ──────────────────────────────────────────────────────────

func TestParseLLMResponse_WellFormed(t *testing.T) {
	f := rule.Finding{RuleID: "SV1010", Severity: rule.SeverityHigh}
	text := `PROBLEM: A secret is hardcoded in env[].value.
SOLUTION: Move the secret to a Kubernetes Secret resource.
YAML:
env:
  - name: MY_SECRET
    valueFrom:
      secretKeyRef:
        name: my-secrets
        key: secret`

	fix := parseLLMResponse(f, text)
	if fix == nil {
		t.Fatal("parseLLMResponse returned nil")
	}
	if fix.Problem != "A secret is hardcoded in env[].value." {
		t.Errorf("Problem: got %q", fix.Problem)
	}
	if fix.Solution != "Move the secret to a Kubernetes Secret resource." {
		t.Errorf("Solution: got %q", fix.Solution)
	}
	if !strings.Contains(fix.YAMLSnippet, "secretKeyRef") {
		t.Errorf("YAMLSnippet missing secretKeyRef, got:\n%s", fix.YAMLSnippet)
	}
	if fix.Source != "llm" {
		t.Errorf("Source: got %q, want llm", fix.Source)
	}
}

func TestParseLLMResponse_MissingProblem_FallsBack(t *testing.T) {
	f := rule.Finding{RuleID: "SV1010", Severity: rule.SeverityHigh, Message: "fallback message"}
	fix := parseLLMResponse(f, "some random text without structure")
	if fix.Problem != "fallback message" {
		t.Errorf("expected fallback to finding.Message, got %q", fix.Problem)
	}
}

func TestParseLLMResponse_NoYAML(t *testing.T) {
	f := rule.Finding{RuleID: "SV1020", Severity: rule.SeverityMedium}
	text := "PROBLEM: High entropy value.\nSOLUTION: Use secretKeyRef."
	fix := parseLLMResponse(f, text)
	if fix.YAMLSnippet != "" {
		t.Errorf("expected empty YAMLSnippet, got %q", fix.YAMLSnippet)
	}
}

// ── GenerateFix ───────────────────────────────────────────────────────────────

func TestGenerateFix_StaticFirst(t *testing.T) {
	f := rule.Finding{RuleID: "SV1010", Severity: rule.SeverityHigh}
	fix, err := GenerateFix(f, "en", false)
	if err != nil {
		t.Fatalf("GenerateFix: %v", err)
	}
	if fix == nil {
		t.Fatal("expected fix, got nil")
	}
	if fix.Source != "static" {
		t.Errorf("expected static fix, got source=%q", fix.Source)
	}
}

func TestGenerateFix_NoTemplateNoLLM(t *testing.T) {
	f := rule.Finding{RuleID: "SV9999", Severity: rule.SeverityLow}
	fix, err := GenerateFix(f, "en", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fix != nil {
		t.Errorf("expected nil fix for unknown rule without LLM, got: %+v", fix)
	}
}

func TestGenerateFix_LLMSkippedWithoutAPIKey(t *testing.T) {
	// If ANTHROPIC_API_KEY is not set, LLMFix returns nil without error
	t.Setenv("ANTHROPIC_API_KEY", "")
	f := rule.Finding{RuleID: "SV9999", Severity: rule.SeverityLow}
	fix, err := GenerateFix(f, "en", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fix != nil {
		t.Errorf("expected nil when ANTHROPIC_API_KEY is unset, got: %+v", fix)
	}
}
