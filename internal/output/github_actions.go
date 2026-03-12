package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/gitscan"
	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
)

// GitHubActionsFormatter emits GitHub Actions workflow commands for inline PR annotations.
// Format: ::error file={file},line={line},title={title}::{message}
// See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
type GitHubActionsFormatter struct{}

// Write outputs GitHub Actions annotation commands for static manifest scan results.
func (f *GitHubActionsFormatter) Write(w io.Writer, result *scanner.ScanResult) error {
	for _, finding := range result.Findings {
		level := ghLevel(finding.Severity)
		file := finding.File
		line := finding.Line
		if line < 1 {
			line = 1
		}
		msg := finding.Message
		if finding.Detail != "" {
			msg += " — " + finding.Detail
		}
		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			level,
			escapeGHValue(file),
			line,
			escapeGHValue(finding.RuleID+": "+finding.Message),
			escapeGHData(msg),
		)
	}

	// Print summary as a notice
	critical, high, medium, low := result.Summary()
	total := critical + high + medium + low
	if total > 0 {
		fmt.Fprintf(w, "::notice title=SecretsVet Summary::%d findings (%d critical, %d high, %d medium, %d low)\n",
			total, critical, high, medium, low)
	}
	return nil
}

// WriteGit outputs GitHub Actions annotation commands for git history scan results.
func (f *GitHubActionsFormatter) WriteGit(w io.Writer, result *gitscan.ScanResult) error {
	for _, finding := range result.Findings {
		level := ghLevelFromStr(string(finding.Severity))
		file := finding.File
		line := finding.Line
		if line < 1 {
			line = 1
		}
		msg := finding.Message
		if finding.CommitHash != "" {
			msg += fmt.Sprintf(" (commit: %s)", finding.CommitHash)
		}
		if finding.Detail != "" {
			msg += " — " + finding.Detail
		}
		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			level,
			escapeGHValue(file),
			line,
			escapeGHValue(finding.RuleID+": "+finding.Message),
			escapeGHData(msg),
		)
	}

	total := len(result.Findings)
	if total > 0 {
		fmt.Fprintf(w, "::notice title=SecretsVet Git Summary::%d findings in %d commits / %d files scanned\n",
			total, result.Commits, result.Files)
	}
	return nil
}

func ghLevel(sev rule.Severity) string {
	switch sev {
	case rule.SeverityCritical, rule.SeverityHigh:
		return "error"
	default:
		return "warning"
	}
}

func ghLevelFromStr(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	default:
		return "warning"
	}
}

// escapeGHValue escapes special characters in GitHub Actions annotation property values.
// Properties must not contain commas, colons, or newlines.
func escapeGHValue(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// escapeGHData escapes special characters in the annotation message data.
func escapeGHData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
