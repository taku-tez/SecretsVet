package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV1040 detects plaintext secrets in ConfigMap data fields.
type configMapDataRule struct{}

func NewConfigMapDataRule() Rule { return &configMapDataRule{} }
func (r *configMapDataRule) ID() string { return "SV1040" }

func (r *configMapDataRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "ConfigMap" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding
	for _, field := range []string{"data", "binaryData"} {
		dataNode, ok := k8s.NodeAt(m, field)
		if !ok {
			continue
		}
		for _, pair := range k8s.MappingPairs(dataNode) {
			keyNode, valNode := pair[0], pair[1]
			key := keyNode.Value
			val := valNode.Value

			if val == "" {
				continue
			}

			if match := detector.MatchAny(val); match != nil {
				findings = append(findings, Finding{
					RuleID:       "SV1040",
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("ConfigMap %s.%s contains a secret pattern (%s)", field, key, match.PatternName),
					File:         res.File,
					Line:         valNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("key: %s, value: %s", key, detector.MaskValue(val)),
				})
			} else if detector.SuspiciousKeyName(key) && len(val) >= 8 {
				findings = append(findings, Finding{
					RuleID:       "SV1040",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("ConfigMap %s.%s has a suspicious key name suggesting it may contain a secret", field, key),
					File:         res.File,
					Line:         valNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("key: %s, value: %s", key, detector.MaskValue(val)),
				})
			} else if detector.IsHighEntropy(val, detector.EntropyMinLength) {
				findings = append(findings, Finding{
					RuleID:       "SV1040",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("ConfigMap %s.%s contains a high-entropy string (possible secret)", field, key),
					File:         res.File,
					Line:         valNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("key: %s, value: %s, entropy: %.2f", key, detector.MaskValue(val), detector.ShannonEntropy(val)),
				})
			}
		}
	}
	return findings
}
