package output

import (
	"fmt"
	"io"

	"github.com/SecretsVet/secretsvet/internal/gitscan"
	"github.com/fatih/color"
)

// GitTTYFormatter writes human-readable colored output for git scan results.
type GitTTYFormatter struct {
	NoColor bool
}

func (f *GitTTYFormatter) WriteGit(w io.Writer, result *gitscan.ScanResult) error {
	if f.NoColor {
		color.NoColor = true
	}

	highColor := color.New(color.FgRed, color.Bold)
	medColor := color.New(color.FgYellow)
	lowColor := color.New(color.FgCyan)

	for _, finding := range result.Findings {
		var sev string
		switch finding.Severity {
		case gitscan.SeverityHigh:
			sev = highColor.Sprint("HIGH  ")
		case gitscan.SeverityMedium:
			sev = medColor.Sprint("MEDIUM")
		case gitscan.SeverityLow:
			sev = lowColor.Sprint("LOW   ")
		}

		location := finding.File
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", finding.File, finding.Line)
		}
		if finding.CommitHash != "" {
			location = fmt.Sprintf("%s [%s]", location, finding.CommitHash)
		}

		fmt.Fprintf(w, "[%s] %s  %s\n", finding.RuleID, sev, location)
		fmt.Fprintf(w, "        %s\n", finding.Message)
		if finding.Detail != "" {
			fmt.Fprintf(w, "        %s\n", color.New(color.Faint).Sprint(finding.Detail))
		}
		fmt.Fprintln(w)
	}

	s := result.Summary()
	if s.Total == 0 {
		color.New(color.FgGreen).Fprintln(w, "No findings in git history.")
	} else {
		fmt.Fprintf(w, "Found %d finding(s) across %d commit(s) in %d file(s)\n",
			s.Total, result.Commits, result.Files)
		fmt.Fprintf(w, "  %s  %s  %s\n",
			highColor.Sprintf("HIGH: %d", s.High),
			medColor.Sprintf("MEDIUM: %d", s.Medium),
			lowColor.Sprintf("LOW: %d", s.Low),
		)
	}

	return nil
}

// GitJSONFormatter writes JSON output for git scan results.
type GitJSONFormatter struct{}

type gitJSONFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	File       string `json:"file"`
	Line       int    `json:"line,omitempty"`
	CommitHash string `json:"commit_hash,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type gitJSONOutput struct {
	RepoPath string           `json:"repo_path"`
	Summary  gitJSONSummary   `json:"summary"`
	Findings []gitJSONFinding `json:"findings"`
}

type gitJSONSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

func (f *GitJSONFormatter) WriteGit(w io.Writer, result *gitscan.ScanResult) error {
	s := result.Summary()
	out := gitJSONOutput{
		RepoPath: result.RepoPath,
		Summary:  gitJSONSummary{Total: s.Total, High: s.High, Medium: s.Medium, Low: s.Low},
	}
	for _, finding := range result.Findings {
		out.Findings = append(out.Findings, gitJSONFinding{
			RuleID:     finding.RuleID,
			Severity:   string(finding.Severity),
			Message:    finding.Message,
			File:       finding.File,
			Line:       finding.Line,
			CommitHash: finding.CommitHash,
			Detail:     finding.Detail,
		})
	}
	if out.Findings == nil {
		out.Findings = []gitJSONFinding{}
	}

	enc := jsonEncoder(w)
	return enc.Encode(out)
}
