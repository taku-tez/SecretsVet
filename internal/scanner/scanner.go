package scanner

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/SecretsVet/secretsvet/internal/config"
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"github.com/SecretsVet/secretsvet/internal/rule"
)

// ScanOptions controls how the scan runs.
type ScanOptions struct {
	Paths       []string
	Recursive   bool
	Kustomize   bool
	HelmCharts  []string       // run `helm template <dir>` on each and scan the output
	MinSeverity rule.Severity
	Config      *config.Config // optional: per-project rule overrides and path ignores
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

	// Collect all resource sources: explicit paths + helm template output
	type source struct {
		resources []*k8s.Resource
		err       error
	}

	var allResources []*k8s.Resource

	for _, path := range opts.Paths {
		resources, err := k8s.LoadPath(path, k8s.LoadOptions{
			Recursive: opts.Recursive,
			Kustomize: opts.Kustomize,
		})
		if err != nil {
			return nil, err
		}
		allResources = append(allResources, resources...)
	}

	// Run `helm template <dir>` for each Helm chart and scan the output
	for _, chartDir := range opts.HelmCharts {
		resources, err := loadHelmTemplate(chartDir)
		if err != nil {
			return nil, fmt.Errorf("helm template %s: %w", chartDir, err)
		}
		allResources = append(allResources, resources...)
	}

	for _, res := range allResources {
		// Apply config path ignores
		if opts.Config != nil && opts.Config.IsPathIgnored(res.File) {
			continue
		}

		if !filesSeen[res.File] {
			filesSeen[res.File] = true
			result.Files++
		}
		result.Resources++

		findings := registry.Check(res)
		for _, f := range findings {
			// Apply config: skip disabled rules
			if opts.Config != nil && opts.Config.IsRuleDisabled(f.RuleID) {
				continue
			}
			// Apply config: override severity
			if opts.Config != nil {
				if sev := opts.Config.SeverityOverride(f.RuleID); sev != "" {
					f.Severity = rule.Severity(sev)
				}
			}
			if severityLevel(f.Severity) >= severityLevel(opts.MinSeverity) {
				result.Findings = append(result.Findings, f)
			}
		}
	}

	return result, nil
}

// loadHelmTemplate runs `helm template <dir>` and parses the output as K8s resources.
func loadHelmTemplate(chartDir string) ([]*k8s.Resource, error) {
	cmd := exec.Command("helm", "template", chartDir)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("helm template: %w", err)
	}
	label := fmt.Sprintf("helm:%s", chartDir)
	return k8s.ParseYAMLString(string(bytes.TrimSpace(out)), label)
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
