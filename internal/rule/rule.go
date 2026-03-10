package rule

import "github.com/SecretsVet/secretsvet/internal/k8s"

// Severity represents the finding severity level.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Finding is a single detected issue.
type Finding struct {
	RuleID       string
	Severity     Severity
	Message      string
	File         string
	Line         int
	ResourceKind string
	ResourceName string
	Namespace    string
	Detail       string // masked value or additional context
}

// Rule is implemented by every detection rule.
type Rule interface {
	ID() string
	Check(res *k8s.Resource) []Finding
}
