package git

import (
	"os"
	"path/filepath"
	"testing"
)

// ── parseHunkStart ────────────────────────────────────────────────────────────

func TestParseHunkStart(t *testing.T) {
	tests := []struct {
		header string
		want   int
	}{
		{"@@ -1,3 +1,5 @@", 1},
		{"@@ -0,0 +1 @@", 1},
		{"@@ -10,4 +15,7 @@ func foo() {", 15},
		{"@@ -1 +42,3 @@", 42},
		{"not a hunk header", 0},
	}
	for _, tt := range tests {
		got := parseHunkStart(tt.header)
		if got != tt.want {
			t.Errorf("parseHunkStart(%q) = %d, want %d", tt.header, got, tt.want)
		}
	}
}

// ── CheckGitignore ────────────────────────────────────────────────────────────

func TestCheckGitignore_NoFile(t *testing.T) {
	dir := t.TempDir()
	// No .gitignore file — all patterns should be missing
	issues, err := CheckGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) == 0 {
		t.Error("expected issues when .gitignore is missing, got none")
	}
}

func TestCheckGitignore_FullCoverage(t *testing.T) {
	dir := t.TempDir()
	content := "*.env\n.env\n*.pem\n*.key\n*.p12\n*.pfx\n*secret*\n*credential*\nkubeconfig\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	issues, err := CheckGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues with full .gitignore, got %d: %v", len(issues), issues)
	}
}

func TestCheckGitignore_PartialCoverage(t *testing.T) {
	dir := t.TempDir()
	// Only covers *.env and .env
	content := "*.env\n.env\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	issues, err := CheckGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) == 0 {
		t.Error("expected issues for uncovered patterns, got none")
	}
	// *.env and .env should be covered
	for _, issue := range issues {
		if issue.MissingPattern == "*.env" || issue.MissingPattern == ".env" {
			t.Errorf("pattern %q should be covered, but reported as missing", issue.MissingPattern)
		}
	}
}

func TestCheckGitignore_CommentLines(t *testing.T) {
	dir := t.TempDir()
	// Comments and blank lines should be ignored
	content := "# This is a comment\n\n*.env\n.env\n# another comment\n*.pem\n*.key\n*.p12\n*.pfx\n*secret*\n*credential*\nkubeconfig\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	issues, err := CheckGitignore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d: %v", len(issues), issues)
	}
}

// ── isCoveredByGitignore ──────────────────────────────────────────────────────

func TestIsCoveredByGitignore(t *testing.T) {
	tests := []struct {
		required string
		lines    []string
		want     bool
	}{
		{"*.env", []string{"*.env"}, true},
		{".env", []string{".env"}, true},
		{"*.pem", []string{"*.pem", "*.key"}, true},
		{"*.env", []string{}, false},
		{"*.env", []string{"!*.env"}, false}, // negation doesn't count
		// Substring coverage: line "**/*.env" contains "*.env"
		{"*.env", []string{"**/*.env"}, true},
	}
	for _, tt := range tests {
		got := isCoveredByGitignore(tt.required, tt.lines)
		if got != tt.want {
			t.Errorf("isCoveredByGitignore(%q, %v) = %v, want %v", tt.required, tt.lines, got, tt.want)
		}
	}
}

// ── IgnoreList ────────────────────────────────────────────────────────────────

func TestIgnoreList_Empty(t *testing.T) {
	il := &IgnoreList{}
	if il.ShouldIgnore("SV1010", "some/file.yaml", "abc123") {
		t.Error("empty IgnoreList should not ignore anything")
	}
}

func TestIgnoreList_RuleID(t *testing.T) {
	il := &IgnoreList{patterns: []string{"SV3010"}}
	if !il.ShouldIgnore("SV3010", "any/file.yaml", "") {
		t.Error("ShouldIgnore should match rule ID")
	}
	if il.ShouldIgnore("SV1010", "any/file.yaml", "") {
		t.Error("ShouldIgnore should not match different rule ID")
	}
}

func TestIgnoreList_CommitHash(t *testing.T) {
	il := &IgnoreList{patterns: []string{"abc1234"}}
	if !il.ShouldIgnore("SV3030", "file.go", "abc1234def456") {
		t.Error("ShouldIgnore should match commit hash prefix")
	}
	if il.ShouldIgnore("SV3030", "file.go", "def1234abc") {
		t.Error("ShouldIgnore should not match different commit")
	}
}

func TestIgnoreList_FilePath(t *testing.T) {
	il := &IgnoreList{patterns: []string{"testdata/*"}}
	if !il.ShouldIgnore("SV3030", "testdata/fixture.yaml", "") {
		t.Error("ShouldIgnore should match file path glob")
	}
	if il.ShouldIgnore("SV3030", "manifests/deploy.yaml", "") {
		t.Error("ShouldIgnore should not match unrelated path")
	}
}

func TestIgnoreList_SubstringPath(t *testing.T) {
	il := &IgnoreList{patterns: []string{"testdata/"}}
	if !il.ShouldIgnore("SV3030", "internal/testdata/fixture.yaml", "") {
		t.Error("ShouldIgnore should match substring path")
	}
}

func TestLoadIgnoreList_NoFile(t *testing.T) {
	dir := t.TempDir()
	il, err := LoadIgnoreList(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if il == nil {
		t.Fatal("expected non-nil IgnoreList")
	}
	if il.ShouldIgnore("SV1010", "file.yaml", "") {
		t.Error("empty list should not ignore anything")
	}
}

func TestLoadIgnoreList_WithFile(t *testing.T) {
	dir := t.TempDir()
	content := "# ignore these\nSV3010\ntestdata/\nabc1234\n"
	if err := os.WriteFile(filepath.Join(dir, ".secretsvet-ignore"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	il, err := LoadIgnoreList(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreList: %v", err)
	}
	if !il.ShouldIgnore("SV3010", "file.yaml", "") {
		t.Error("expected SV3010 to be ignored")
	}
	if !il.ShouldIgnore("SV3030", "testdata/fixture.yaml", "") {
		t.Error("expected testdata/ path to be ignored")
	}
}

// ── IsRepo ────────────────────────────────────────────────────────────────────

func TestIsRepo_Valid(t *testing.T) {
	// The SecretsVet source itself is a git repo
	if !IsRepo(".") {
		t.Error("expected current directory to be a git repo")
	}
}

func TestIsRepo_Invalid(t *testing.T) {
	dir := t.TempDir()
	if IsRepo(dir) {
		t.Error("expected temp dir to not be a git repo")
	}
}

// ── ScanHistoryRange smoke test ───────────────────────────────────────────────

func TestScanHistoryRange_EmptyRepo(t *testing.T) {
	dir := t.TempDir()
	// Not a git repo — ScanHistoryRange will fail gracefully via ScanHistory
	// We just ensure it doesn't panic
	err := ScanHistoryRange(dir, "", func(_ DiffLine) {})
	// Expected to fail since it's not a git repo, but shouldn't panic
	_ = err
}

func TestScanHistory_CurrentRepo(t *testing.T) {
	// Smoke test: scan just the most recent commit in the current repo
	var lines []DiffLine
	// Use a range that limits to nothing (HEAD..HEAD = empty)
	err := ScanHistoryRange(".", "HEAD", func(line DiffLine) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatalf("ScanHistoryRange: %v", err)
	}
	// HEAD..HEAD should produce no diff lines
	if len(lines) != 0 {
		t.Errorf("HEAD..HEAD should produce no lines, got %d", len(lines))
	}
}

// ── ListCommittedFiles smoke test ────────────────────────────────────────────

func TestListCommittedFiles_NotARepo(t *testing.T) {
	dir := t.TempDir()
	_, err := ListCommittedFiles(dir, "*.env")
	// Should return an error, not panic
	_ = err
}

