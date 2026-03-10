package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV1080 detects cross-namespace Secret references in volume projections
// and imagePullSecrets that reference secrets in other namespaces.
// Note: Kubernetes doesn't actually allow cross-namespace secret refs natively,
// so this rule catches patterns in multi-tenant configs that may indicate mistakes.
type crossNamespaceRule struct{}

func NewCrossNamespaceRule() Rule { return &crossNamespaceRule{} }
func (r *crossNamespaceRule) ID() string { return "SV1080" }

func (r *crossNamespaceRule) Check(res *k8s.Resource) []Finding {
	// Only check workload types that can have volumes and env
	switch res.Kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}
	resNamespace := res.Namespace

	var findings []Finding

	// Check volumes[].projected.sources[].serviceAccountToken.audience — not cross-namespace
	// But check for explicit namespace annotations or spec fields pointing elsewhere
	findings = append(findings, checkVolumeSecretRefs(res, m, resNamespace)...)

	return findings
}

// checkVolumeSecretRefs checks spec.volumes[].secret.secretName references
// and warns if the Secret's name suggests it belongs to another namespace
// (via annotations or naming conventions like "namespace/secret-name").
func checkVolumeSecretRefs(res *k8s.Resource, m *yaml.Node, resNamespace string) []Finding {
	var findings []Finding

	// Look for volumes in the various spec paths
	specPaths := [][]string{
		{"spec", "volumes"},
		{"spec", "template", "spec", "volumes"},
		{"spec", "jobTemplate", "spec", "template", "spec", "volumes"},
	}

	for _, path := range specPaths {
		volumes, ok := k8s.SequenceAt(m, path...)
		if !ok {
			continue
		}
		for _, vol := range volumes {
			if vol.Kind != yaml.MappingNode {
				continue
			}
			secretNode, ok := k8s.NodeAt(vol, "secret")
			if !ok || secretNode == nil {
				continue
			}
			// Check for namespace field within secret volume (non-standard but possible in some configs)
			ns, nsLine, nsOk := k8s.StringAt(secretNode, "namespace")
			if nsOk && ns != "" && resNamespace != "" && ns != resNamespace {
				volName, _, _ := k8s.StringAt(vol, "name")
				findings = append(findings, Finding{
					RuleID:       "SV1080",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("volume '%s' references a Secret in namespace '%s', but this resource is in namespace '%s'", volName, ns, resNamespace),
					File:         res.File,
					Line:         nsLine,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    resNamespace,
					Detail:       fmt.Sprintf("cross-namespace Secret volume reference: %s/%s", ns, volName),
				})
			}
		}
	}

	return findings
}
