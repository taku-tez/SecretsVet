package git

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreList holds patterns from a .secretsvet-ignore file.
type IgnoreList struct {
	patterns []string
}

// LoadIgnoreList reads .secretsvet-ignore from the repo root.
// Returns an empty list if the file does not exist.
func LoadIgnoreList(repoPath string) (*IgnoreList, error) {
	path := filepath.Join(repoPath, ".secretsvet-ignore")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return &IgnoreList{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return &IgnoreList{patterns: patterns}, sc.Err()
}

// ShouldIgnore returns true if the given file path or content matches an ignore rule.
// Rules can be:
//   - File path glob patterns (e.g. "testdata/**")
//   - Rule IDs (e.g. "SV3010")
//   - Commit hashes (e.g. "abc1234")
func (il *IgnoreList) ShouldIgnore(ruleID, filePath, commitHash string) bool {
	for _, pattern := range il.patterns {
		// Exact rule ID match
		if pattern == ruleID {
			return true
		}
		// Commit hash prefix match
		if len(pattern) >= 7 && strings.HasPrefix(commitHash, pattern) {
			return true
		}
		// File path glob match
		matched, err := filepath.Match(pattern, filePath)
		if err == nil && matched {
			return true
		}
		// Prefix match for directory patterns
		if strings.HasSuffix(pattern, "/") && strings.HasPrefix(filePath, pattern) {
			return true
		}
		// Simple substring for paths (e.g. "testdata/")
		if strings.Contains(filePath, pattern) {
			return true
		}
	}
	return false
}
