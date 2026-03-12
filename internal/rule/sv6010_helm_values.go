package rule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/detector"
	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV6010 detects plaintext secrets in Helm values.yaml / values-*.yaml files.
type helmValuesRule struct{}

func NewHelmValuesRule() Rule { return &helmValuesRule{} }
func (r *helmValuesRule) ID() string { return "SV6010" }

func (r *helmValuesRule) Check(res *k8s.Resource) []Finding {
	base := filepath.Base(res.File)
	if !isHelmValuesFile(base) {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}
	return scanHelmValuesNode(res, m, "")
}

func isHelmValuesFile(name string) bool {
	lower := strings.ToLower(name)
	if lower == "values.yaml" || lower == "values.yml" {
		return true
	}
	for _, tmpl := range []string{"values-*.yaml", "values-*.yml", "values_*.yaml", "values_*.yml"} {
		if ok, _ := filepath.Match(tmpl, lower); ok {
			return true
		}
	}
	return false
}

// scanHelmValuesNode recursively walks a YAML mapping and reports suspicious values.
func scanHelmValuesNode(res *k8s.Resource, m *yaml.Node, prefix string) []Finding {
	var findings []Finding
	for _, pair := range k8s.MappingPairs(m) {
		keyNode, valNode := pair[0], pair[1]
		key := keyNode.Value
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch valNode.Kind {
		case yaml.ScalarNode:
			val := valNode.Value
			if val == "" || isHelmPlaceholder(val) {
				continue
			}
			findings = append(findings, checkHelmScalar(res, fullKey, val, valNode.Line)...)

		case yaml.MappingNode:
			findings = append(findings, scanHelmValuesNode(res, valNode, fullKey)...)

		case yaml.SequenceNode:
			for i, item := range valNode.Content {
				if item.Kind == yaml.MappingNode {
					findings = append(findings, scanHelmValuesNode(res, item, fmt.Sprintf("%s[%d]", fullKey, i))...)
				} else if item.Kind == yaml.ScalarNode {
					val := item.Value
					if val != "" && !isHelmPlaceholder(val) {
						findings = append(findings, checkHelmScalar(res, fmt.Sprintf("%s[%d]", fullKey, i), val, item.Line)...)
					}
				}
			}
		}
	}
	return findings
}

func checkHelmScalar(res *k8s.Resource, key, val string, line int) []Finding {
	suspiciousKey := detector.SuspiciousKeyName(key)

	// Known pattern match — HIGH regardless of key name
	if m := detector.MatchAny(val); m != nil {
		sev := SeverityHigh
		if !suspiciousKey {
			sev = SeverityMedium
		}
		return []Finding{{
			RuleID:       "SV6010",
			Severity:     sev,
			Message:      fmt.Sprintf("Helm values file contains a secret pattern (%s) at key %q", m.PatternName, key),
			File:         res.File,
			Line:         line,
			ResourceKind: "HelmValues",
			ResourceName: res.Name,
			Detail:       fmt.Sprintf("key: %s, value: %s", key, detector.MaskValue(val)),
		}}
	}

	// Suspicious key name + high entropy → MEDIUM
	if suspiciousKey && detector.IsHighEntropy(val, detector.EntropyMinLength) {
		return []Finding{{
			RuleID:       "SV6010",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("Helm values file contains a high-entropy value at suspicious key %q", key),
			File:         res.File,
			Line:         line,
			ResourceKind: "HelmValues",
			ResourceName: res.Name,
			Detail:       fmt.Sprintf("key: %s, value: %s, entropy: %.2f", key, detector.MaskValue(val), detector.ShannonEntropy(val)),
		}}
	}

	// Suspicious key name + non-trivial non-placeholder value → LOW
	if suspiciousKey && len([]rune(val)) >= 8 {
		return []Finding{{
			RuleID:       "SV6010",
			Severity:     SeverityLow,
			Message:      fmt.Sprintf("Helm values file has a non-empty value at suspicious key %q — verify it is not a secret", key),
			File:         res.File,
			Line:         line,
			ResourceKind: "HelmValues",
			ResourceName: res.Name,
			Detail:       fmt.Sprintf("key: %s, value: %s", key, detector.MaskValue(val)),
		}}
	}

	return nil
}

// isHelmPlaceholder returns true for common placeholder / template values.
func isHelmPlaceholder(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	switch lower {
	case "changeme", "placeholder", "null", "~", "true", "false",
		"<your-value>", "your-value", "todo", "fixme", "replace-me",
		"change-me", "override-me", "example", "sample":
		return true
	}
	// Helm template expression: {{ .Values.xxx }}
	if strings.HasPrefix(val, "{{") && strings.HasSuffix(strings.TrimSpace(val), "}}") {
		return true
	}
	// Numeric only
	isNum := true
	for _, c := range val {
		if c < '0' || c > '9' {
			isNum = false
			break
		}
	}
	return isNum
}
