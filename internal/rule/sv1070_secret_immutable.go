package rule

import (
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV1070 warns when a Secret does not have immutable: true set.
type secretImmutableRule struct{}

func NewSecretImmutableRule() Rule { return &secretImmutableRule{} }
func (r *secretImmutableRule) ID() string { return "SV1070" }

func (r *secretImmutableRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "Secret" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	val, line, ok := k8s.StringAt(m, "immutable")
	if ok && val == "true" {
		return nil
	}

	// Point to the Secret resource line (metadata.name line)
	if line == 0 {
		if _, l, ok := k8s.StringAt(m, "metadata", "name"); ok {
			line = l
		}
	}

	return []Finding{
		{
			RuleID:       "SV1070",
			Severity:     SeverityLow,
			Message:      "Secret does not have 'immutable: true' — setting this prevents accidental modification and improves etcd performance",
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "add 'immutable: true' to the Secret manifest",
		},
	}
}
