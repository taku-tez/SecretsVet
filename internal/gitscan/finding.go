// Package gitscan orchestrates scanning of git repository history for secrets.
package gitscan

// Severity mirrors rule.Severity but is redeclared to avoid circular imports.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding represents a single secret detection in git history.
type Finding struct {
	RuleID     string
	Severity   Severity
	Message    string
	File       string
	Line       int
	CommitHash string // abbreviated 8-char hash
	Detail     string
}

// Summary counts findings by severity.
type Summary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// ScanResult holds all findings from a git scan.
type ScanResult struct {
	RepoPath string
	Findings []Finding
	Commits  int
	Files    int
}

func (r *ScanResult) Summary() Summary {
	s := Summary{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		}
	}
	return s
}
