package git

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GitignoreIssue describes a missing or weak pattern in .gitignore.
type GitignoreIssue struct {
	MissingPattern string
	Description    string
}

// RequiredGitignorePatterns are patterns that should be present in .gitignore
// for a project handling secrets.
var requiredGitignorePatterns = []struct {
	pattern     string
	description string
}{
	{"*.env", "environment files with secrets"},
	{".env", ".env file with secrets"},
	{"*.pem", "PEM private key files"},
	{"*.key", "private key files"},
	{"*.p12", "PKCS12 certificate files"},
	{"*.pfx", "PFX certificate files"},
	{"*secret*", "files with 'secret' in the name"},
	{"*credential*", "files with 'credential' in the name"},
	{"kubeconfig", "kubeconfig with cluster credentials"},
}

// CheckGitignore reads .gitignore and returns issues for missing secret-protection patterns.
func CheckGitignore(repoPath string) ([]GitignoreIssue, error) {
	path := filepath.Join(repoPath, ".gitignore")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		// No .gitignore at all — report all missing patterns
		var issues []GitignoreIssue
		for _, req := range requiredGitignorePatterns {
			issues = append(issues, GitignoreIssue{
				MissingPattern: req.pattern,
				Description:    req.description,
			})
		}
		return issues, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read all non-comment, non-empty lines
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	var issues []GitignoreIssue
	for _, req := range requiredGitignorePatterns {
		if !isCoveredByGitignore(req.pattern, lines) {
			issues = append(issues, GitignoreIssue{
				MissingPattern: req.pattern,
				Description:    req.description,
			})
		}
	}
	return issues, nil
}

// isCoveredByGitignore checks if the required pattern is covered by existing gitignore lines.
func isCoveredByGitignore(required string, lines []string) bool {
	for _, line := range lines {
		// Exact match
		if line == required {
			return true
		}
		// Negation rules don't count
		if strings.HasPrefix(line, "!") {
			continue
		}
		// Check if the gitignore line matches the required pattern as a path
		matched, err := filepath.Match(line, required)
		if err == nil && matched {
			return true
		}
		// Wildcard coverage: "**/*.env" covers "*.env"
		if strings.Contains(line, required) {
			return true
		}
	}
	return false
}
