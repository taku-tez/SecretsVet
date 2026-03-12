package gitscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// initRepo creates a temporary git repository and returns its path.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test User")
	run("config", "commit.gpgsign", "false")
	return dir
}

// addAndCommit writes a file and creates a git commit.
func addAndCommit(t *testing.T, dir, name, content, message string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", name)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", message)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

// ── Scan: not a repo ──────────────────────────────────────────────────────────

func TestScan_NotARepo(t *testing.T) {
	dir := t.TempDir()
	_, err := Scan(ScanOptions{RepoPath: dir})
	if err == nil {
		t.Error("expected error for non-git directory, got nil")
	}
}

// ── Scan: SV3010 – missing .gitignore patterns ────────────────────────────────

func TestScan_SV3010_MissingGitignore(t *testing.T) {
	dir := initRepo(t)

	// Commit a README but no .gitignore
	addAndCommit(t, dir, "README.md", "# test\n", "init")

	result, err := Scan(ScanOptions{RepoPath: dir, SkipHistory: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SV3010" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SV3010 for missing .gitignore patterns, got none")
	}
}

func TestScan_SV3010_SuppressedByGitignore(t *testing.T) {
	dir := initRepo(t)

	// Full .gitignore coverage
	gitignore := "*.env\n.env\n*.pem\n*.key\n*.p12\n*.pfx\n*secret*\n*credential*\nkubeconfig\n"
	addAndCommit(t, dir, ".gitignore", gitignore, "add full .gitignore")

	result, err := Scan(ScanOptions{RepoPath: dir, SkipHistory: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, f := range result.Findings {
		if f.RuleID == "SV3010" {
			t.Errorf("SV3010 should not fire with full .gitignore, got: %s", f.Message)
		}
	}
}

// ── Scan: SV3020 – .env committed ────────────────────────────────────────────

func TestScan_SV3020_EnvFileCommitted(t *testing.T) {
	dir := initRepo(t)

	// Commit a .env file
	addAndCommit(t, dir, ".env", "DB_PASSWORD=hunter2\n", "add env file")

	result, err := Scan(ScanOptions{RepoPath: dir, SkipHistory: false})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SV3020" {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("SV3020 severity: got %q, want CRITICAL", f.Severity)
			}
			if f.CommitHash == "" {
				t.Error("SV3020 CommitHash should not be empty")
			}
			break
		}
	}
	if !found {
		t.Error("expected SV3020 for committed .env file, got none")
	}
}

// ── Scan: SV3030 – secret pattern in history ─────────────────────────────────

func TestScan_SV3030_SecretInHistory(t *testing.T) {
	dir := initRepo(t)

	// Commit a file containing an AWS access key pattern
	addAndCommit(t, dir, "config.txt", "aws_key=AKIAIOSFODNN7EXAMPLE\n", "add config")

	result, err := Scan(ScanOptions{RepoPath: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SV3030" || f.RuleID == "SV3050" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SV3030/SV3050 for AWS key in history, got none")
	}
}

// ── Scan: SkipHistory ─────────────────────────────────────────────────────────

func TestScan_SkipHistory(t *testing.T) {
	dir := initRepo(t)
	addAndCommit(t, dir, "secret.txt", "AKIAIOSFODNN7EXAMPLE\n", "add secret")

	result, err := Scan(ScanOptions{RepoPath: dir, SkipHistory: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// With SkipHistory, SV3030 should not appear
	for _, f := range result.Findings {
		if f.RuleID == "SV3030" || f.RuleID == "SV3050" {
			t.Errorf("SkipHistory should prevent history scan, got %s", f.RuleID)
		}
	}
	// Stats should be zero
	if result.Commits != 0 || result.Files != 0 {
		t.Errorf("SkipHistory: expected 0 commits/files, got %d/%d", result.Commits, result.Files)
	}
}

// ── ScanResult.Summary ────────────────────────────────────────────────────────

func TestScanResult_Summary(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
			{Severity: SeverityLow},
		},
	}
	s := result.Summary()
	if s.Total != 5 {
		t.Errorf("Total: got %d, want 5", s.Total)
	}
	if s.Critical != 2 {
		t.Errorf("Critical: got %d, want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High: got %d, want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium: got %d, want 1", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("Low: got %d, want 1", s.Low)
	}
}

// ── extractSecretTokens ───────────────────────────────────────────────────────

func TestExtractSecretTokens_Assignment(t *testing.T) {
	// A line with an assignment should extract the value token
	tokens := extractSecretTokens("api_key=AKIAIOSFODNN7EXAMPLE")
	if len(tokens) == 0 {
		t.Error("expected tokens from assignment line, got none")
	}
	found := false
	for _, tok := range tokens {
		if tok == "AKIAIOSFODNN7EXAMPLE" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AKIAIOSFODNN7EXAMPLE in tokens, got %v", tokens)
	}
}

func TestExtractSecretTokens_SkipsShortTokens(t *testing.T) {
	tokens := extractSecretTokens("key=short")
	for _, tok := range tokens {
		if len(tok) < 20 {
			t.Errorf("token %q is shorter than minLen 20", tok)
		}
	}
}

func TestExtractSecretTokens_SkipsNonASCII(t *testing.T) {
	// Japanese text should not produce tokens
	tokens := extractSecretTokens("コメント: これはテスト")
	if len(tokens) != 0 {
		t.Errorf("non-ASCII line should produce no tokens, got %v", tokens)
	}
}

func TestExtractSecretTokens_SkipsModulePaths(t *testing.T) {
	tokens := extractSecretTokens("import github.com/user/repo/internal/pkg")
	for _, tok := range tokens {
		t.Errorf("module path line should produce no tokens, got %q", tok)
	}
}

// ── isKnownSafeFile ───────────────────────────────────────────────────────────

func TestIsKnownSafeFile(t *testing.T) {
	safe := []string{"go.sum", "package-lock.json", "yarn.lock", "Pipfile.lock"}
	for _, f := range safe {
		if !isKnownSafeFile(f) {
			t.Errorf("isKnownSafeFile(%q) = false, want true", f)
		}
	}
	unsafe := []string{"secret.yaml", "values.yaml", ".env"}
	for _, f := range unsafe {
		if isKnownSafeFile(f) {
			t.Errorf("isKnownSafeFile(%q) = true, want false", f)
		}
	}
}

// ── helper predicates ─────────────────────────────────────────────────────────

func TestIsAlphaOnly(t *testing.T) {
	if !isAlphaOnly("abcXYZ") {
		t.Error("isAlphaOnly(abcXYZ) should be true")
	}
	if isAlphaOnly("abc123") {
		t.Error("isAlphaOnly(abc123) should be false")
	}
	if isAlphaOnly("") {
		// empty string: all chars trivially satisfy → true; just ensure no panic
	}
}

func TestIsSecretCharset(t *testing.T) {
	if !isSecretCharset("AKIAIOSFODNN7EXAMPLE") {
		t.Error("isSecretCharset: expected true for AWS-style key")
	}
	if isSecretCharset("map[string]bool") {
		t.Error("isSecretCharset: expected false for Go code construct")
	}
}

func TestIsASCIIOnly(t *testing.T) {
	if !isASCIIOnly("hello world 123") {
		t.Error("isASCIIOnly: expected true for ASCII string")
	}
	if isASCIIOnly("日本語") {
		t.Error("isASCIIOnly: expected false for non-ASCII string")
	}
}

func TestLooksLikeModulePath(t *testing.T) {
	if !looksLikeModulePath("github.com/user/repo") {
		t.Error("looksLikeModulePath: expected true for github.com path")
	}
	if !looksLikeModulePath("internal/pkg/thing") {
		t.Error("looksLikeModulePath: expected true for internal/ path")
	}
	if looksLikeModulePath("AKIAIOSFODNN7EXAMPLE") {
		t.Error("looksLikeModulePath: expected false for AWS key")
	}
}
