package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV6030 detects plaintext secrets in Kustomize secretGenerator literals.
// secretGenerator.literals[] entries have the form "KEY=value". If the value
// contains a known secret pattern or the key is suspicious, we flag it.
type kustomizeSecretGenLiteralRule struct{}

func NewKustomizeSecretGenLiteralRule() Rule { return &kustomizeSecretGenLiteralRule{} }
func (r *kustomizeSecretGenLiteralRule) ID() string { return "SV6030" }

func (r *kustomizeSecretGenLiteralRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "Kustomization" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	secretGens, ok := k8s.SequenceAt(m, "secretGenerator")
	if !ok {
		return nil
	}

	var findings []Finding
	for _, gen := range secretGens {
		genName, _, _ := k8s.StringAt(gen, "name")

		literals, ok := k8s.SequenceAt(gen, "literals")
		if !ok {
			continue
		}

		for _, litNode := range literals {
			literal := litNode.Value
			key, val, ok := parseLiteral(literal)
			if !ok || val == "" || isHelmPlaceholder(val) {
				continue
			}

			if m := detector.MatchAny(val); m != nil {
				findings = append(findings, Finding{
					RuleID:       "SV6030",
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("secretGenerator %q literal %q contains a secret pattern (%s)", genName, key, m.PatternName),
					File:         res.File,
					Line:         litNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("generator: %s, key: %s, value: %s", genName, key, detector.MaskValue(val)),
				})
				continue
			}

			if detector.IsHighEntropy(val, detector.EntropyMinLength) {
				findings = append(findings, Finding{
					RuleID:       "SV6030",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("secretGenerator %q literal %q contains a high-entropy value (possible secret)", genName, key),
					File:         res.File,
					Line:         litNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("generator: %s, key: %s, value: %s, entropy: %.2f", genName, key, detector.MaskValue(val), detector.ShannonEntropy(val)),
				})
				continue
			}

			if detector.SuspiciousKeyName(key) && len([]rune(val)) >= 8 {
				findings = append(findings, Finding{
					RuleID:       "SV6030",
					Severity:     SeverityLow,
					Message:      fmt.Sprintf("secretGenerator %q literal %q has a suspicious key with non-empty value — verify it is not a plaintext secret", genName, key),
					File:         res.File,
					Line:         litNode.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       fmt.Sprintf("generator: %s, key: %s, value: %s", genName, key, detector.MaskValue(val)),
				})
			}
		}
	}
	return findings
}

// parseLiteral splits a "KEY=value" literal entry into key and value.
// Returns ok=false if the format is not as expected.
func parseLiteral(s string) (key, val string, ok bool) {
	idx := strings.Index(s, "=")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), s[idx+1:], true
}
