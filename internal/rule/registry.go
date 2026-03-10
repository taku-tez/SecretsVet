package rule

import "github.com/SecretsVet/secretsvet/internal/k8s"

// Registry holds all rules and runs them against a resource.
type Registry struct {
	rules []Rule
}

// NewRegistry returns a Registry with all v0.1.0 rules registered.
func NewRegistry() *Registry {
	return &Registry{
		rules: []Rule{
			NewEnvRegexRule(),
			NewEnvEntropyRule(),
			NewArgsSecretsRule(),
			NewConfigMapDataRule(),
			NewEnvFromSourceRule(),
			NewSecretEntropyRule(),
			NewSecretImmutableRule(),
			NewCrossNamespaceRule(),
		},
	}
}

// Check runs all rules against a resource and returns all findings.
func (r *Registry) Check(res *k8s.Resource) []Finding {
	var findings []Finding
	for _, rule := range r.rules {
		findings = append(findings, rule.Check(res)...)
	}
	return findings
}
