package rule

import "github.com/SecretsVet/secretsvet/internal/k8s"

// Registry holds all rules and runs them against a resource.
type Registry struct {
	rules []Rule
}

// NewRegistry returns a Registry with all rules registered.
func NewRegistry() *Registry {
	return &Registry{
		rules: []Rule{
			// v0.1.0 — Static manifest detection
			NewEnvRegexRule(),
			NewEnvEntropyRule(),
			NewArgsSecretsRule(),
			NewConfigMapDataRule(),
			NewEnvFromSourceRule(),
			NewSecretEntropyRule(),
			NewSecretImmutableRule(),
			NewCrossNamespaceRule(),
			// v0.2.0 — External Secrets validation
			NewESKeyRefRule(),
			NewStoreConfigRule(),
			NewRefreshIntervalRule(),
			NewCreationPolicyRule(),
			NewKeyTypoRule(),
			NewVaultPathRule(),
			NewVaultRoleRule(),
			NewLeaseRenewalRule(),
			NewIAMOverPermRule(),
			NewRotationRule(),
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
