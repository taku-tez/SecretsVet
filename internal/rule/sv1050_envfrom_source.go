package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV1050 warns when envFrom references a ConfigMap (not a Secret).
// ConfigMaps are not encrypted at rest; sensitive data should use Secrets.
type envFromSourceRule struct{}

func NewEnvFromSourceRule() Rule { return &envFromSourceRule{} }
func (r *envFromSourceRule) ID() string { return "SV1050" }

func (r *envFromSourceRule) Check(res *k8s.Resource) []Finding {
	var findings []Finding
	for _, containers := range k8s.ContainerPaths(res.Node) {
		for _, container := range containers {
			findings = append(findings, checkEnvFrom(res, container)...)
		}
	}
	return findings
}

func checkEnvFrom(res *k8s.Resource, container *yaml.Node) []Finding {
	var findings []Finding
	envFromItems, ok := k8s.SequenceAt(container, "envFrom")
	if !ok {
		return nil
	}
	containerName, _, _ := k8s.StringAt(container, "name")
	for _, item := range envFromItems {
		if item.Kind != yaml.MappingNode {
			continue
		}
		cmRefNode, hasCMRef := k8s.NodeAt(item, "configMapRef")
		if !hasCMRef || cmRefNode == nil {
			continue
		}
		cmName, _, _ := k8s.StringAt(cmRefNode, "name")
		findings = append(findings, Finding{
			RuleID:       "SV1050",
			Severity:     SeverityMedium,
			Message:      "envFrom references a ConfigMap; ConfigMaps are not encrypted at rest — use a Secret for sensitive values",
			File:         res.File,
			Line:         cmRefNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("container: %s, configMapRef: %s", containerName, cmName),
		})
	}
	return findings
}
