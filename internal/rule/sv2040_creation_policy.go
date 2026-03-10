package rule

import (
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV2040 detects CreationPolicy: Merge which can unintentionally overwrite
// existing Secret keys when the ExternalSecret syncs.
type creationPolicyRule struct{}

func NewCreationPolicyRule() Rule { return &creationPolicyRule{} }
func (r *creationPolicyRule) ID() string { return "SV2040" }

func (r *creationPolicyRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "ExternalSecret", "ClusterExternalSecret":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	policy, line, ok := k8s.StringAt(m, "spec", "target", "creationPolicy")
	if !ok {
		return nil
	}

	if policy == "Merge" {
		return []Finding{{
			RuleID:       "SV2040",
			Severity:     SeverityMedium,
			Message:      "ExternalSecret uses creationPolicy: Merge — this can silently overwrite existing Secret keys on sync",
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "use 'Owner' (default) unless merging into an existing Secret is explicitly required; document the intent clearly",
		}}
	}

	return nil
}
