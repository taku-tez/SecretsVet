// Package git provides utilities for scanning git repository history.
package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CommitFile represents a file path changed in a commit.
type CommitFile struct {
	CommitHash string
	FilePath   string
}

// DiffLine represents a single added line in a git diff.
type DiffLine struct {
	CommitHash string
	FilePath   string
	LineNumber int
	Content    string
}

// IsRepo returns true if the given path is inside a git repository.
func IsRepo(repoPath string) bool {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

// ListAllCommits returns all commit hashes in the repo (including all branches/tags).
func ListAllCommits(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoPath, "rev-list", "--all")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}
	var hashes []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		h := strings.TrimSpace(sc.Text())
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	return hashes, nil
}

// ScanHistory streams all added lines from git history through the provided callback.
// It runs `git log --all -p` and parses the unified diff output.
// The callback receives each added line. Return true from callback to continue, false to stop.
func ScanHistory(repoPath string, cb func(line DiffLine)) error {
	return ScanHistoryRange(repoPath, "", cb)
}

// ScanHistoryRange is like ScanHistory but limits to commits reachable from HEAD
// that are not reachable from sinceCommit. If sinceCommit is empty, all history is scanned.
// This is equivalent to `git log <sinceCommit>..HEAD`.
func ScanHistoryRange(repoPath, sinceCommit string, cb func(line DiffLine)) error {
	var revRange string
	if sinceCommit != "" {
		revRange = sinceCommit + "..HEAD"
	}

	args := []string{"-C", repoPath, "log"}
	if sinceCommit != "" {
		// Range mode: only commits between sinceCommit and HEAD
		args = append(args, revRange)
	} else {
		// Full history across all refs
		args = append(args, "--all", "--full-history")
	}
	args = append(args, "--format=COMMIT:%H", "-p", "--no-color", "--diff-filter=AM")

	// Use --no-color to ensure clean output, --diff-filter includes all changes
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		// git log returns exit code 128 on empty repos
		if len(out) == 0 {
			return nil
		}
		return fmt.Errorf("git log -p: %w", err)
	}

	var (
		currentCommit string
		currentFile   string
		addedLineNum  int
	)

	sc := bufio.NewScanner(bytes.NewReader(out))
	// Increase buffer for large diffs
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for sc.Scan() {
		line := sc.Text()

		if strings.HasPrefix(line, "COMMIT:") {
			currentCommit = strings.TrimPrefix(line, "COMMIT:")
			currentFile = ""
			addedLineNum = 0
			continue
		}

		// Diff file header: +++ b/path/to/file
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			addedLineNum = 0
			continue
		}
		if strings.HasPrefix(line, "+++ /dev/null") {
			currentFile = ""
			continue
		}

		// Hunk header: @@ -old +new @@
		if strings.HasPrefix(line, "@@ ") {
			// Parse new file start line: @@ -a,b +c,d @@
			addedLineNum = parseHunkStart(line)
			continue
		}

		// Context line (unchanged)
		if strings.HasPrefix(line, " ") {
			addedLineNum++
			continue
		}

		// Added line
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:] // strip leading +
			cb(DiffLine{
				CommitHash: currentCommit,
				FilePath:   currentFile,
				LineNumber: addedLineNum,
				Content:    content,
			})
			addedLineNum++
			continue
		}

		// Removed line (-)
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			// Don't increment addedLineNum for removed lines
			continue
		}
	}

	return sc.Err()
}

// parseHunkStart extracts the new-file start line number from a hunk header.
// Format: @@ -old_start[,old_count] +new_start[,new_count] @@ ...
func parseHunkStart(header string) int {
	// Find "+N" or "+N,M" part
	start := strings.Index(header, " +")
	if start < 0 {
		return 0
	}
	rest := header[start+2:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	num := 0
	for _, ch := range rest[:end] {
		if ch >= '0' && ch <= '9' {
			num = num*10 + int(ch-'0')
		}
	}
	return num
}

// ListCommittedFiles returns all files ever committed matching the given glob patterns.
// Uses `git log --all --name-only --diff-filter=A` to find files added in history.
func ListCommittedFiles(repoPath string, patterns ...string) ([]CommitFile, error) {
	args := []string{"-C", repoPath, "log", "--all", "--name-only",
		"--format=COMMIT:%H", "--diff-filter=A", "--"}
	args = append(args, patterns...)

	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log --name-only: %w", err)
	}

	var files []CommitFile
	var currentHash string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "COMMIT:") {
			currentHash = strings.TrimPrefix(line, "COMMIT:")
			continue
		}
		files = append(files, CommitFile{CommitHash: currentHash, FilePath: line})
	}
	return files, nil
}
