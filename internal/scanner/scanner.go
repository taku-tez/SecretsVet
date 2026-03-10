package scanner

import (
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"github.com/SecretsVet/secretsvet/internal/rule"
)

// ScanOptions controls how the scan runs.
type ScanOptions struct {
	Paths       []string
	Recursive   bool
	Kustomize   bool
	MinSeverity rule.Severity
}

// ScanResult holds all findings and statistics from a scan.
type ScanResult struct {
	Findings  []rule.Finding
	Files     int
	Resources int
}

// Scan loads all resources from the given paths and runs all rules.
func Scan(opts ScanOptions) (*ScanResult, error) {
	registry := rule.NewRegistry()
	result := &ScanResult{}

	filesSeen := make(map[string]bool)

	for _, path := range opts.Paths {
		resources, err := k8s.LoadPath(path, k8s.LoadOptions{
			Recursive: opts.Recursive,
			Kustomize: opts.Kustomize,
		})
		if err != nil {
			return nil, err
		}

		for _, res := range resources {
			if !filesSeen[res.File] {
				filesSeen[res.File] = true
				result.Files++
			}
			result.Resources++

			findings := registry.Check(res)
			for _, f := range findings {
				if severityLevel(f.Severity) >= severityLevel(opts.MinSeverity) {
					result.Findings = append(result.Findings, f)
				}
			}
		}
	}

	return result, nil
}

func severityLevel(s rule.Severity) int {
	switch s {
	case rule.SeverityCritical:
		return 4
	case rule.SeverityHigh:
		return 3
	case rule.SeverityMedium:
		return 2
	case rule.SeverityLow:
		return 1
	}
	return 0
}

// Summary returns counts by severity.
func (r *ScanResult) Summary() (critical, high, medium, low int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case rule.SeverityCritical:
			critical++
		case rule.SeverityHigh:
			high++
		case rule.SeverityMedium:
			medium++
		case rule.SeverityLow:
			low++
		}
	}
	return
}
