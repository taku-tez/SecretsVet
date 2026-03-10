package rule

import (
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV2080 warns when VaultDynamicSecret does not configure leaseRenewalPercent.
// Without it, the lease may expire before renewal is attempted.
type leaseRenewalRule struct{}

func NewLeaseRenewalRule() Rule { return &leaseRenewalRule{} }
func (r *leaseRenewalRule) ID() string { return "SV2080" }

func (r *leaseRenewalRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "VaultDynamicSecret" {
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	_, hasRenewal := k8s.NodeAt(m, "spec", "leaseRenewalPercent")
	if hasRenewal {
		return nil
	}

	// Get the line from spec itself for the finding location
	line := 0
	if specNode, ok := k8s.NodeAt(m, "spec"); ok && specNode != nil {
		line = specNode.Line
	}

	return []Finding{{
		RuleID:       "SV2080",
		Severity:     SeverityMedium,
		Message:      "VaultDynamicSecret does not configure spec.leaseRenewalPercent — lease may expire before renewal",
		File:         res.File,
		Line:         line,
		ResourceKind: res.Kind,
		ResourceName: res.Name,
		Namespace:    res.Namespace,
		Detail:       "set spec.leaseRenewalPercent (e.g. 67) to renew at 67% of the lease duration",
	}}
}
