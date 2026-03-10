package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2070 detects overly broad Vault role permissions in VaultAuth resources.
// Also checks VaultStaticSecret/VaultDynamicSecret for wildcard role bindings.
type vaultRoleRule struct{}

func NewVaultRoleRule() Rule { return &vaultRoleRule{} }
func (r *vaultRoleRule) ID() string { return "SV2070" }

func (r *vaultRoleRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "VaultAuth":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding

	// Check kubernetes auth role
	role, roleLine, roleOk := k8s.StringAt(m, "spec", "kubernetes", "role")
	if roleOk && role != "" {
		if f := checkVaultRoleName(res, role, roleLine); f != nil {
			findings = append(findings, *f)
		}
	}

	// Check bound service accounts — wildcard is dangerous
	sas, ok := k8s.SequenceAt(m, "spec", "kubernetes", "serviceAccountNames")
	if ok {
		for _, sa := range sas {
			if sa.Kind == yaml.ScalarNode && (sa.Value == "*" || sa.Value == "") {
				findings = append(findings, Finding{
					RuleID:       "SV2070",
					Severity:     SeverityHigh,
					Message:      "VaultAuth kubernetes serviceAccountNames contains wildcard '*' — any service account can authenticate",
					File:         res.File,
					Line:         sa.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       "restrict serviceAccountNames to specific service accounts",
				})
			}
		}
	}

	// Check policies — if policies are specified inline and include wildcards or admin
	policies, ok := k8s.SequenceAt(m, "spec", "kubernetes", "policies")
	if ok {
		for _, p := range policies {
			if p.Kind != yaml.ScalarNode {
				continue
			}
			pol := p.Value
			if pol == "root" || pol == "*" {
				findings = append(findings, Finding{
					RuleID:       "SV2070",
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("VaultAuth kubernetes policy %q grants excessive permissions", pol),
					File:         res.File,
					Line:         p.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       "use the principle of least privilege — create a scoped Vault policy",
				})
			} else if strings.Contains(pol, "admin") || strings.Contains(pol, "superuser") {
				findings = append(findings, Finding{
					RuleID:       "SV2070",
					Severity:     SeverityMedium,
					Message:      fmt.Sprintf("VaultAuth kubernetes policy %q suggests broad administrative access", pol),
					File:         res.File,
					Line:         p.Line,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					Namespace:    res.Namespace,
					Detail:       "verify this policy only grants read access to the required secret paths",
				})
			}
		}
	}

	return findings
}

func checkVaultRoleName(res *k8s.Resource, role string, line int) *Finding {
	suspicious := []string{"admin", "root", "superuser", "god", "all", "*"}
	roleLower := strings.ToLower(role)
	for _, s := range suspicious {
		if roleLower == s || strings.HasSuffix(roleLower, "-"+s) {
			return &Finding{
				RuleID:       "SV2070",
				Severity:     SeverityMedium,
				Message:      fmt.Sprintf("VaultAuth references potentially overprivileged Vault role: %q", role),
				File:         res.File,
				Line:         line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       "use a scoped Vault role with read-only access to the required paths only",
			}
		}
	}
	return nil
}
