package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("/nonexistent/.secretsvet.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	content := `
rules:
  SV6040:
    disabled: true
  SV1070:
    severity: HIGH

thresholds:
  entropy_min_length: 24

ignore:
  paths:
    - tests/**
    - "**/*_test.yaml"
`
	cfgPath := filepath.Join(dir, ".secretsvet.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.IsRuleDisabled("SV6040") {
		t.Error("SV6040 should be disabled")
	}
	if cfg.IsRuleDisabled("SV1010") {
		t.Error("SV1010 should not be disabled")
	}
	if cfg.SeverityOverride("SV1070") != "HIGH" {
		t.Errorf("SV1070 severity override: got %q, want HIGH", cfg.SeverityOverride("SV1070"))
	}
	if cfg.SeverityOverride("SV1010") != "" {
		t.Error("SV1010 should have no severity override")
	}
	if cfg.EntropyMinLength() != 24 {
		t.Errorf("entropy_min_length: got %d, want 24", cfg.EntropyMinLength())
	}
}

func TestIsPathIgnored(t *testing.T) {
	cfg := &Config{
		Ignore: IgnoreConfig{
			Paths: []string{
				"tests/**",
				"**/*_test.yaml",
				"vendor/",
			},
		},
	}

	hits := []string{
		"tests/fixtures/deploy.yaml",
		"tests/a/b/c.yaml",
		"deploy_test.yaml",
	}
	misses := []string{
		"manifests/deploy.yaml",
		"deploy.yaml",
		"internal/rule/sv1010.go",
	}

	for _, p := range hits {
		if !cfg.IsPathIgnored(p) {
			t.Errorf("IsPathIgnored(%q) = false, want true", p)
		}
	}
	for _, p := range misses {
		if cfg.IsPathIgnored(p) {
			t.Errorf("IsPathIgnored(%q) = true, want false", p)
		}
	}
}

func TestNilConfig(t *testing.T) {
	var cfg *Config
	if cfg.IsRuleDisabled("SV1010") {
		t.Error("nil config should not disable any rule")
	}
	if cfg.SeverityOverride("SV1010") != "" {
		t.Error("nil config should have no severity override")
	}
	if cfg.IsPathIgnored("foo.yaml") {
		t.Error("nil config should not ignore any path")
	}
	if cfg.EntropyMinLength() != 0 {
		t.Error("nil config entropy min length should be 0")
	}
}
