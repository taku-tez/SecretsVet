// Package clusterscan orchestrates live Kubernetes cluster security checks.
package clusterscan

// Severity levels for cluster scan findings.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Finding is a single issue detected in a live cluster.
type Finding struct {
	RuleID       string
	Severity     Severity
	Message      string
	ResourceKind string
	ResourceName string
	Namespace    string
	Detail       string
}

// ScanResult holds all findings from a cluster scan.
type ScanResult struct {
	Context  string
	Findings []Finding
}

// Summary counts findings by severity.
func (r *ScanResult) Summary() (high, medium, low int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		case SeverityLow:
			low++
		}
	}
	return
}
