package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV1020 detects high-entropy strings in env[].value fields.
type envEntropyRule struct{}

func NewEnvEntropyRule() Rule { return &envEntropyRule{} }
func (r *envEntropyRule) ID() string { return "SV1020" }

func (r *envEntropyRule) Check(res *k8s.Resource) []Finding {
	var findings []Finding
	for _, containers := range k8s.ContainerPaths(res.Node) {
		for _, container := range containers {
			findings = append(findings, checkEnvEntropy(res, container)...)
		}
	}
	return findings
}

func checkEnvEntropy(res *k8s.Resource, container *yaml.Node) []Finding {
	var findings []Finding
	envItems, ok := k8s.SequenceAt(container, "env")
	if !ok {
		return nil
	}
	for _, item := range envItems {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if _, hasFrom := k8s.NodeAt(item, "valueFrom"); hasFrom {
			continue
		}
		val, line, ok := k8s.StringAt(item, "value")
		if !ok || val == "" {
			continue
		}
		// Skip Kubernetes variable references like $(VAR_NAME)
		if strings.HasPrefix(val, "$(") && strings.HasSuffix(val, ")") {
			continue
		}
		// Skip if already caught by SV1010
		if detector.MatchAny(val) != nil {
			continue
		}
		name, _, _ := k8s.StringAt(item, "name")
		if detector.IsHighEntropy(val, detector.EntropyMinLength) {
			findings = append(findings, Finding{
				RuleID:       "SV1020",
				Severity:     SeverityMedium,
				Message:      "env[].value contains a high-entropy string (possible secret)",
				File:         res.File,
				Line:         line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("env var: %s, value: %s, entropy: %.2f", name, detector.MaskValue(val), detector.ShannonEntropy(val)),
			})
		}
	}
	return findings
}
