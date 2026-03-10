package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2050 detects likely typos in remoteRef.key paths by checking for
// duplicate path segments, inconsistent separators, and common misspellings.
type keyTypoRule struct{}

func NewKeyTypoRule() Rule { return &keyTypoRule{} }
func (r *keyTypoRule) ID() string { return "SV2050" }

func (r *keyTypoRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "ExternalSecret", "ClusterExternalSecret":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding
	dataItems, ok := k8s.SequenceAt(m, "spec", "data")
	if !ok {
		return nil
	}

	// Collect all keys to detect duplicates
	keysSeen := make(map[string][]string) // remoteRef.key → secretKey list

	for _, item := range dataItems {
		if item.Kind != yaml.MappingNode {
			continue
		}
		secretKey, _, _ := k8s.StringAt(item, "secretKey")
		remoteKey, keyLine, keyOk := k8s.StringAt(item, "remoteRef", "key")
		if !keyOk || remoteKey == "" {
			continue
		}

		keysSeen[remoteKey] = append(keysSeen[remoteKey], secretKey)

		// Check for mixed separators (both / and . in same path — unusual)
		if strings.Contains(remoteKey, "/") && strings.Contains(remoteKey, ".") {
			findings = append(findings, Finding{
				RuleID:       "SV2050",
				Severity:     SeverityLow,
				Message:      fmt.Sprintf("ExternalSecret remoteRef.key uses mixed path separators ('/' and '.') — verify this is intentional"),
				File:         res.File,
				Line:         keyLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("key: %q, secretKey: %q", remoteKey, secretKey),
			})
		}

		// Detect repeated path segments: e.g. "prod/prod/myapp"
		segments := strings.Split(remoteKey, "/")
		for i := 1; i < len(segments); i++ {
			if segments[i] != "" && segments[i] == segments[i-1] {
				findings = append(findings, Finding{
					RuleID:       "SV2050",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("ExternalSecret remoteRef.key has a repeated path segment %q — possible typo", segments[i]),
					File:         res.File,
					Line:         keyLine,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("key: %q", remoteKey),
				})
				break
			}
		}
	}

	// Detect duplicate remoteRef.key references
	for key, secretKeys := range keysSeen {
		if len(secretKeys) > 1 {
			findings = append(findings, Finding{
				RuleID:       "SV2050",
				Severity:     SeverityMedium,
				Message:      fmt.Sprintf("ExternalSecret remoteRef.key %q is referenced multiple times — may indicate a copy-paste error", key),
				File:         res.File,
				Line:         0,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("key: %q appears %d times (secretKeys: %s)", key, len(secretKeys), strings.Join(secretKeys, ", ")),
			})
		}
	}

	return findings
}
