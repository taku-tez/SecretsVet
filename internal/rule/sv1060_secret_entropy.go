package rule

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV1060 detects high-entropy values in Opaque Secret data fields.
type secretEntropyRule struct{}

func NewSecretEntropyRule() Rule { return &secretEntropyRule{} }
func (r *secretEntropyRule) ID() string { return "SV1060" }

func (r *secretEntropyRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "Secret" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	// Only check Opaque type (or absent type, which defaults to Opaque)
	secretType, _, _ := k8s.StringAt(m, "type")
	if secretType != "" && secretType != "Opaque" {
		return nil
	}

	var findings []Finding
	dataNode, ok := k8s.NodeAt(m, "data")
	if !ok {
		// Try stringData for unencoded secrets
		dataNode, ok = k8s.NodeAt(m, "stringData")
		if !ok {
			return nil
		}
	}

	for _, pair := range k8s.MappingPairs(dataNode) {
		keyNode, valNode := pair[0], pair[1]
		key := keyNode.Value
		val := valNode.Value
		if val == "" {
			continue
		}

		// Try base64 decode
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val))
		checkVal := val
		if err == nil {
			checkVal = string(decoded)
		}

		if match := detector.MatchAny(checkVal); match != nil {
			findings = append(findings, Finding{
				RuleID:       "SV1060",
				Severity:     SeverityHigh,
				Message:      fmt.Sprintf("Secret data.%s contains a known secret pattern (%s) in its decoded value", key, match.PatternName),
				File:         res.File,
				Line:         valNode.Line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("key: %s", key),
			})
		} else if detector.IsHighEntropy(checkVal, detector.EntropyMinLength) {
			findings = append(findings, Finding{
				RuleID:       "SV1060",
				Severity:     SeverityMedium,
				Message:      fmt.Sprintf("Secret data.%s contains a high-entropy value (confirmed secret stored in manifest)", key),
				File:         res.File,
				Line:         valNode.Line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("key: %s, entropy: %.2f", key, detector.ShannonEntropy(checkVal)),
			})
		}
	}
	return findings
}
