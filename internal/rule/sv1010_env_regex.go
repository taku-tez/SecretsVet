package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV1010 detects secret patterns in env[].value fields.
type envRegexRule struct{}

func NewEnvRegexRule() Rule { return &envRegexRule{} }
func (r *envRegexRule) ID() string { return "SV1010" }

func (r *envRegexRule) Check(res *k8s.Resource) []Finding {
	var findings []Finding
	for _, containers := range k8s.ContainerPaths(res.Node) {
		for _, container := range containers {
			findings = append(findings, checkEnvRegex(res, container)...)
		}
	}
	return findings
}

func checkEnvRegex(res *k8s.Resource, container *yaml.Node) []Finding {
	var findings []Finding
	envItems, ok := k8s.SequenceAt(container, "env")
	if !ok {
		return nil
	}
	for _, item := range envItems {
		if item.Kind != yaml.MappingNode {
			continue
		}
		// Skip if valueFrom is set (not a literal value)
		if _, hasFrom := k8s.NodeAt(item, "valueFrom"); hasFrom {
			continue
		}
		val, line, ok := k8s.StringAt(item, "value")
		if !ok || val == "" {
			continue
		}
		name, _, _ := k8s.StringAt(item, "name")
		if m := detector.MatchAny(val); m != nil {
			findings = append(findings, Finding{
				RuleID:       "SV1010",
				Severity:     SeverityHigh,
				Message:      fmt.Sprintf("env[].value contains a secret pattern (%s)", m.PatternName),
				File:         res.File,
				Line:         line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("env var: %s, value: %s", name, detector.MaskValue(val)),
			})
		}
	}
	return findings
}
