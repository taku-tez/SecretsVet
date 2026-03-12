package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/config"
	"github.com/SecretsVet/secretsvet/internal/rule"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ── basic scan ────────────────────────────────────────────────────────────────

func TestScan_Clean(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: clean-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          env:
            - name: LOG_LEVEL
              value: info`)

	result, err := Scan(ScanOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Non-suspicious env var should not trigger
	for _, f := range result.Findings {
		if f.RuleID == "SV1010" || f.RuleID == "SV1020" {
			t.Errorf("unexpected finding %s: %s", f.RuleID, f.Message)
		}
	}
}

func TestScan_DetectsSecretInEnv(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          env:
            - name: AWS_ACCESS_KEY_ID
              value: AKIAIOSFODNN7EXAMPLE`)

	result, err := Scan(ScanOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SV1010" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SV1010 finding for AWS key in env, got none")
	}
}

func TestScan_Stats(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "a.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: s1`)
	writeYAML(t, dir, "b.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: s2`)

	result, err := Scan(ScanOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Files != 2 {
		t.Errorf("Files: got %d, want 2", result.Files)
	}
	if result.Resources != 2 {
		t.Errorf("Resources: got %d, want 2", result.Resources)
	}
}

// ── min severity filter ───────────────────────────────────────────────────────

func TestScan_MinSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	// SV1070 is LOW, SV1010 is HIGH
	writeYAML(t, dir, "mixed.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: c2VjcmV0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp
          env:
            - name: AWS_KEY
              value: AKIAIOSFODNN7EXAMPLE`)

	result, err := Scan(ScanOptions{
		Paths:       []string{dir},
		MinSeverity: rule.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range result.Findings {
		if f.Severity == rule.SeverityLow || f.Severity == rule.SeverityMedium {
			t.Errorf("finding below min severity: %s %s", f.RuleID, f.Severity)
		}
	}
}

// ── config: disabled rule ─────────────────────────────────────────────────────

func TestScan_ConfigDisabledRule(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  password: c2VjcmV0`)

	// Without config: SV1070 (not immutable) fires
	result, err := Scan(ScanOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	foundSV1070 := false
	for _, f := range result.Findings {
		if f.RuleID == "SV1070" {
			foundSV1070 = true
			break
		}
	}
	if !foundSV1070 {
		t.Skip("SV1070 not triggered — skipping config disable test")
	}

	// With config: SV1070 disabled
	cfg := &config.Config{
		Rules: map[string]config.RuleConfig{
			"SV1070": {Disabled: true},
		},
	}
	result2, err := Scan(ScanOptions{Paths: []string{dir}, Config: cfg})
	if err != nil {
		t.Fatalf("Scan with config: %v", err)
	}
	for _, f := range result2.Findings {
		if f.RuleID == "SV1070" {
			t.Error("SV1070 should be disabled by config, but it appeared in findings")
		}
	}
}

// ── config: severity override ─────────────────────────────────────────────────

func TestScan_ConfigSeverityOverride(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  password: c2VjcmV0`)

	cfg := &config.Config{
		Rules: map[string]config.RuleConfig{
			"SV1070": {Severity: "CRITICAL"},
		},
	}
	result, err := Scan(ScanOptions{Paths: []string{dir}, Config: cfg})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "SV1070" {
			if f.Severity != rule.SeverityCritical {
				t.Errorf("SV1070 severity override: got %q, want CRITICAL", f.Severity)
			}
			return
		}
	}
}

// ── config: path ignore ───────────────────────────────────────────────────────

func TestScan_ConfigPathIgnore(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "tests")
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Secret in tests/ dir
	writeYAML(t, testDir, "fixture.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp
          env:
            - name: AWS_KEY
              value: AKIAIOSFODNN7EXAMPLE`)

	// Without config: findings in tests/
	result, err := Scan(ScanOptions{Paths: []string{dir}, Recursive: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings without config path ignore")
	}

	// With config: tests/** ignored
	cfg := &config.Config{
		Ignore: config.IgnoreConfig{Paths: []string{"tests/**"}},
	}
	result2, err := Scan(ScanOptions{Paths: []string{dir}, Recursive: true, Config: cfg})
	if err != nil {
		t.Fatalf("Scan with ignore: %v", err)
	}
	for _, f := range result2.Findings {
		if strings.HasPrefix(f.File, testDir) {
			t.Errorf("finding in ignored path: %s", f.File)
		}
	}
}

// ── multiple paths ────────────────────────────────────────────────────────────

func TestScan_MultiplePaths(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeYAML(t, dir1, "a.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: s1`)
	writeYAML(t, dir2, "b.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: s2`)

	result, err := Scan(ScanOptions{Paths: []string{dir1, dir2}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Files != 2 {
		t.Errorf("Files: got %d, want 2", result.Files)
	}
}

// ── summary ───────────────────────────────────────────────────────────────────

func TestScanResult_Summary(t *testing.T) {
	result := &ScanResult{
		Findings: []rule.Finding{
			{Severity: rule.SeverityCritical},
			{Severity: rule.SeverityHigh},
			{Severity: rule.SeverityHigh},
			{Severity: rule.SeverityMedium},
			{Severity: rule.SeverityLow},
		},
	}
	critical, high, medium, low := result.Summary()
	if critical != 1 {
		t.Errorf("critical: got %d, want 1", critical)
	}
	if high != 2 {
		t.Errorf("high: got %d, want 2", high)
	}
	if medium != 1 {
		t.Errorf("medium: got %d, want 1", medium)
	}
	if low != 1 {
		t.Errorf("low: got %d, want 1", low)
	}
}

// ── stdin path ("-") ──────────────────────────────────────────────────────────

func TestScan_StdinPath(t *testing.T) {
	yaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: stdin-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp
          env:
            - name: AWS_ACCESS_KEY_ID
              value: AKIAIOSFODNN7EXAMPLE`

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() { os.Stdin = origStdin }()

	result, err := Scan(ScanOptions{Paths: []string{"-"}})
	if err != nil {
		t.Fatalf("Scan stdin: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SV1010" {
			found = true
		}
	}
	if !found {
		t.Error("expected SV1010 from stdin scan, got none")
	}
}
