package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV1030 detects secrets embedded in container args[] and command[].
type argsSecretsRule struct{}

func NewArgsSecretsRule() Rule { return &argsSecretsRule{} }
func (r *argsSecretsRule) ID() string { return "SV1030" }

func (r *argsSecretsRule) Check(res *k8s.Resource) []Finding {
	var findings []Finding
	for _, containers := range k8s.ContainerPaths(res.Node) {
		for _, container := range containers {
			findings = append(findings, checkArgsSecrets(res, container)...)
		}
	}
	return findings
}

func checkArgsSecrets(res *k8s.Resource, container *yaml.Node) []Finding {
	var findings []Finding
	for _, field := range []string{"args", "command"} {
		items, ok := k8s.SequenceAt(container, field)
		if !ok {
			continue
		}
		for _, item := range items {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			val := item.Value
			if val == "" {
				continue
			}
			if m := detector.MatchAny(val); m != nil {
				findings = append(findings, Finding{
					RuleID:       "SV1030",
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("%s[] contains a secret pattern (%s)", field, m.PatternName),
					File:         res.File,
					Line:         item.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("field: %s, value: %s", field, detector.MaskValue(val)),
				})
			} else if detector.IsHighEntropy(val, detector.EntropyMinLength) {
				findings = append(findings, Finding{
					RuleID:       "SV1030",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("%s[] contains a high-entropy string (possible secret)", field),
					File:         res.File,
					Line:         item.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("field: %s, value: %s, entropy: %.2f", field, detector.MaskValue(val), detector.ShannonEntropy(val)),
				})
			}
		}
	}
	return findings
}
