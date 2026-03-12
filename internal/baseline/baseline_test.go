package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SecretsVet/secretsvet/internal/rule"
)

var (
	f1 = rule.Finding{RuleID: "SV1010", File: "k8s/deploy.yaml", ResourceKind: "Deployment", ResourceName: "myapp", Namespace: "prod", Message: "env var has secret"}
	f2 = rule.Finding{RuleID: "SV1070", File: "k8s/secret.yaml", ResourceKind: "Secret", ResourceName: "mysecret", Namespace: "prod", Message: "not immutable"}
	f3 = rule.Finding{RuleID: "SV6010", File: "values.yaml", ResourceKind: "HelmValues", Message: "plaintext password"}
)

func TestFingerprint_Stable(t *testing.T) {
	fp1a := Fingerprint(f1)
	fp1b := Fingerprint(f1)
	if fp1a != fp1b {
		t.Errorf("fingerprint not stable: %q vs %q", fp1a, fp1b)
	}
}

func TestFingerprint_Distinct(t *testing.T) {
	fp1 := Fingerprint(f1)
	fp2 := Fingerprint(f2)
	if fp1 == fp2 {
		t.Errorf("different findings have same fingerprint: %q", fp1)
	}
}

func TestFingerprint_LineNumberIgnored(t *testing.T) {
	a := rule.Finding{RuleID: "SV1070", File: "k8s/secret.yaml", ResourceKind: "Secret", ResourceName: "x", Line: 10}
	b := rule.Finding{RuleID: "SV1070", File: "k8s/secret.yaml", ResourceKind: "Secret", ResourceName: "x", Line: 42}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("fingerprint should be identical regardless of line number")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	findings := []rule.Finding{f1, f2, f3}
	if err := Save(path, findings); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline file not created: %v", err)
	}

	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(b.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(b.Entries))
	}
	if !b.Contains(f1) {
		t.Error("baseline should contain f1")
	}
	if !b.Contains(f2) {
		t.Error("baseline should contain f2")
	}
	if !b.Contains(f3) {
		t.Error("baseline should contain f3")
	}
}

func TestLoad_NotExist(t *testing.T) {
	b, err := Load("/nonexistent/baseline.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if b.Contains(f1) {
		t.Error("empty baseline should not contain anything")
	}
}

func TestFilter(t *testing.T) {
	all := []rule.Finding{f1, f2, f3}

	// Baseline only contains f1 and f2
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	_ = Save(path, []rule.Finding{f1, f2})
	b, _ := Load(path)

	filtered := Filter(all, b)
	if len(filtered) != 1 {
		t.Errorf("expected 1 new finding, got %d: %v", len(filtered), filtered)
	}
	if filtered[0].RuleID != "SV6010" {
		t.Errorf("expected SV6010 as new finding, got %s", filtered[0].RuleID)
	}
}

func TestFilter_NilBaseline(t *testing.T) {
	all := []rule.Finding{f1, f2}
	result := Filter(all, nil)
	if len(result) != 2 {
		t.Errorf("nil baseline should not filter anything, got %d findings", len(result))
	}
}
