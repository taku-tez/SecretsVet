package gitscan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/git"
)

// Silence unused import warnings
var _ = filepath.Base

// ScanOptions controls the git history scan.
type ScanOptions struct {
	RepoPath    string
	MaxCommits  int    // 0 = unlimited
	SkipHistory bool   // skip commit history, only check working tree files
	SinceCommit string // if set, only scan commits reachable from HEAD but not from this SHA (e.g. base branch SHA for PRs)
}

// Scan runs all git-history checks and returns findings.
func Scan(opts ScanOptions) (*ScanResult, error) {
	if !git.IsRepo(opts.RepoPath) {
		return nil, fmt.Errorf("%s is not a git repository", opts.RepoPath)
	}

	ignoreList, err := git.LoadIgnoreList(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("load .secretsvet-ignore: %w", err)
	}

	result := &ScanResult{RepoPath: opts.RepoPath}

	// 1. Check .gitignore for missing secret patterns
	result.Findings = append(result.Findings, scanGitignore(opts.RepoPath, ignoreList)...)

	if !opts.SkipHistory {
		// 2. Scan all committed .env files
		result.Findings = append(result.Findings, scanEnvFiles(opts.RepoPath, ignoreList)...)

		// 3. Scan git history for secrets in diff lines
		histFindings, commits, files, err := scanHistory(opts.RepoPath, opts.MaxCommits, opts.SinceCommit, ignoreList)
		if err != nil {
			return nil, err
		}
		result.Findings = append(result.Findings, histFindings...)
		result.Commits = commits
		result.Files = files
	}

	return result, nil
}

// scanGitignore checks .gitignore for missing secret-protection patterns.
func scanGitignore(repoPath string, ignore *git.IgnoreList) []Finding {
	issues, err := git.CheckGitignore(repoPath)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, issue := range issues {
		if ignore.ShouldIgnore("SV3010", ".gitignore", "") {
			continue
		}
		findings = append(findings, Finding{
			RuleID:   "SV3010",
			Severity: SeverityMedium,
			Message:  fmt.Sprintf(".gitignore is missing a pattern for %s (%s)", issue.MissingPattern, issue.Description),
			File:     ".gitignore",
			Detail:   fmt.Sprintf("add '%s' to .gitignore to prevent accidental commits", issue.MissingPattern),
		})
	}
	return findings
}

// scanEnvFiles checks whether .env or .env.* files were ever committed.
func scanEnvFiles(repoPath string, ignore *git.IgnoreList) []Finding {
	patterns := []string{"*.env", ".env", ".env.*", ".env.local", ".env.production", ".env.development"}
	files, err := git.ListCommittedFiles(repoPath, patterns...)
	if err != nil {
		return nil
	}

	var findings []Finding
	seen := make(map[string]bool)
	for _, cf := range files {
		key := cf.FilePath + ":" + cf.CommitHash[:min(8, len(cf.CommitHash))]
		if seen[key] {
			continue
		}
		seen[key] = true

		if ignore.ShouldIgnore("SV3020", cf.FilePath, cf.CommitHash) {
			continue
		}

		short := cf.CommitHash
		if len(short) > 8 {
			short = short[:8]
		}
		findings = append(findings, Finding{
			RuleID:     "SV3020",
			Severity:   SeverityCritical,
			Message:    fmt.Sprintf("File '%s' was committed to git history", cf.FilePath),
			File:       cf.FilePath,
			CommitHash: short,
			Detail:     fmt.Sprintf("commit: %s — environment files often contain plaintext secrets; add to .gitignore and rotate any exposed values", short),
		})
	}
	return findings
}

// scanHistory scans all added lines in git history for secrets.
func scanHistory(repoPath string, maxCommits int, sinceCommit string, ignore *git.IgnoreList) ([]Finding, int, int, error) {
	var findings []Finding
	commitsSeen := make(map[string]bool)
	filesSeen := make(map[string]bool)

	// Deduplicate findings to avoid flooding output when the same secret appears in many commits
	type findingKey struct {
		file    string
		content string
		ruleID  string
	}
	seen := make(map[findingKey]bool)

	err := git.ScanHistoryRange(repoPath, sinceCommit, func(line git.DiffLine) {
		if line.CommitHash == "" || line.FilePath == "" {
			return
		}
		if maxCommits > 0 && len(commitsSeen) >= maxCommits {
			return
		}

		commitsSeen[line.CommitHash] = true
		filesSeen[line.FilePath] = true

		// Skip known non-secret file types
		if isKnownSafeFile(line.FilePath) {
			return
		}

		content := strings.TrimSpace(line.Content)
		if content == "" {
			return
		}

		short := line.CommitHash
		if len(short) > 8 {
			short = short[:8]
		}

		// Check for known secret patterns (full line)
		if m := detector.MatchAny(content); m != nil {
			ruleID := ruleIDForFile(line.FilePath, "SV3030")
			if ignore.ShouldIgnore(ruleID, line.FilePath, line.CommitHash) {
				return
			}
			k := findingKey{file: line.FilePath, content: content[:min(40, len(content))], ruleID: ruleID}
			if !seen[k] {
				seen[k] = true
				findings = append(findings, Finding{
					RuleID:     ruleID,
					Severity:   SeverityCritical,
					Message:    fmt.Sprintf("Secret pattern '%s' found in git history", m.PatternName),
					File:       line.FilePath,
					Line:       line.LineNumber,
					CommitHash: short,
					Detail:     fmt.Sprintf("commit: %s, value: %s", short, detector.MaskValue(content)),
				})
			}
			return
		}

		// For entropy checks, extract candidate tokens (space/quote/= delimited)
		// to avoid false positives from natural language text (especially non-ASCII).
		for _, token := range extractSecretTokens(content) {
			if !detector.IsHighEntropy(token, detector.EntropyMinLength) {
				continue
			}
			ruleID := ruleIDForFile(line.FilePath, "SV3040")
			if ignore.ShouldIgnore(ruleID, line.FilePath, line.CommitHash) {
				continue
			}
			k := findingKey{file: line.FilePath, content: token[:min(40, len(token))], ruleID: ruleID}
			if !seen[k] {
				seen[k] = true
				findings = append(findings, Finding{
					RuleID:     ruleID,
					Severity:   SeverityMedium,
					Message:    "High-entropy token found in git history (possible secret)",
					File:       line.FilePath,
					Line:       line.LineNumber,
					CommitHash: short,
					Detail:     fmt.Sprintf("commit: %s, value: %s, entropy: %.2f", short, detector.MaskValue(token), detector.ShannonEntropy(token)),
				})
			}
		}
	})
	if err != nil {
		return nil, 0, 0, err
	}

	return findings, len(commitsSeen), len(filesSeen), nil
}

// extractSecretTokens extracts candidate secret tokens from a line.
// Only returns discrete tokens (no spaces) that look like they could be secrets:
// - Pure alphanumeric/base64/hex strings (no spaces, min 20 chars)
// - Values after = or : separators that are whitespace-free
// This filters out natural language text and code identifiers.
func extractSecretTokens(line string) []string {
	seen := make(map[string]bool)
	var tokens []string

	addToken := func(t string) {
		// Strip surrounding quotes and common punctuation
		t = strings.Trim(t, `"'` + "`.,;()[]{}\\|<>!#@~^")
		// Must be contiguous (no spaces), ASCII-only, and meet minimum length
		if !isASCIIOnly(t) || strings.ContainsAny(t, " \t\r\n") {
			return
		}
		if len(t) < detector.EntropyMinLength {
			return
		}
		// Secrets must be "pure" — only alphanumeric plus base64/hex extras (+/=_-)
		// Code constructs (map[string]bool, func(), etc.) contain structural chars
		if !isSecretCharset(t) {
			return
		}
		// Skip tokens that are all-alpha (no digits → likely a word or identifier)
		if isAlphaOnly(t) {
			return
		}
		// Skip tokens that look like Go module paths or domain names
		// These have dots and slashes but are not secrets
		if looksLikeModulePath(t) {
			return
		}
		if !seen[t] {
			seen[t] = true
			tokens = append(tokens, t)
		}
	}

	// Extract value after assignment operators (= or :)
	for _, sep := range []string{" = ", "=", ": ", ":"} {
		idx := strings.Index(line, sep)
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len(sep):])
		// Only take the first space-delimited word after the separator
		word := strings.Fields(rest)
		if len(word) > 0 {
			addToken(word[0])
		}
	}

	// Also scan all whitespace-delimited tokens in the line
	for _, word := range strings.Fields(line) {
		addToken(word)
	}

	return tokens
}

// isAlphaOnly returns true if the string contains only ASCII letters.
func isAlphaOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

// isKnownSafeFile returns true for file types that are expected to contain
// high-entropy data but are not secrets (go.sum, package-lock.json, etc.).
func isKnownSafeFile(filePath string) bool {
	base := filepath.Base(filePath)
	safeFiles := map[string]bool{
		"go.sum":           true,
		"package-lock.json": true,
		"yarn.lock":        true,
		"Pipfile.lock":     true,
		"poetry.lock":      true,
		"Gemfile.lock":     true,
		"composer.lock":    true,
	}
	return safeFiles[base]
}

// looksLikeModulePath returns true if a token looks like a Go module path,
// URL, or package import path (e.g. github.com/user/repo/pkg).
func looksLikeModulePath(t string) bool {
	// Contains a TLD-like pattern: .com/, .io/, .org/, .net/, .dev/
	for _, tld := range []string{".com/", ".io/", ".org/", ".net/", ".dev/", ".xyz/"} {
		if strings.Contains(t, tld) {
			return true
		}
	}
	// Looks like a Go module path segment: internal/, cmd/, pkg/
	for _, seg := range []string{"internal/", "cmd/", "pkg/", "vendor/"} {
		if strings.Contains(t, seg) {
			return true
		}
	}
	// Has ://
	if strings.Contains(t, "://") {
		return true
	}
	return false
}

// isSecretCharset returns true if the string only contains characters that
// appear in secrets (alphanumeric, base64 extras +/=, hex, underscores, hyphens, dots).
// This filters out code constructs like map[string]bool, func(), etc.
func isSecretCharset(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z': // upper alpha
		case c >= 'a' && c <= 'z': // lower alpha
		case c >= '0' && c <= '9': // digits
		case c == '+' || c == '/' || c == '=': // base64
		case c == '-' || c == '_' || c == '.': // common in API keys/tokens
		default:
			return false
		}
	}
	return true
}

// isASCIIOnly returns true if the string contains only ASCII characters (0x00–0x7F).
func isASCIIOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// ruleIDForFile returns a specialized rule ID based on the file type.
func ruleIDForFile(filePath, defaultID string) string {
	base := strings.ToLower(filepath.Base(filePath))
	switch {
	case base == "values.yaml" || base == "values.yml" || strings.Contains(filePath, "helm"):
		if defaultID == "SV3030" {
			return "SV3050"
		}
		return "SV3050"
	}
	return defaultID
}

// scanHelmValues placeholder (Helm values are already caught via scanHistory).
func scanHelmValues(_ []Finding) []Finding { return nil }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
