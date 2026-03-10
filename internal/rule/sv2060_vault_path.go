package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV2060 validates path configuration in VaultStaticSecret and VaultDynamicSecret.
type vaultPathRule struct{}

func NewVaultPathRule() Rule { return &vaultPathRule{} }
func (r *vaultPathRule) ID() string { return "SV2060" }

func (r *vaultPathRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "VaultStaticSecret", "VaultDynamicSecret":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding

	// mount is required
	mount, mountLine, mountOk := k8s.StringAt(m, "spec", "mount")
	if !mountOk || mount == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2060",
			Severity:     SeverityHigh,
			Message:      fmt.Sprintf("%s is missing spec.mount — Vault secrets engine mount path is required", res.Kind),
			File:         res.File,
			Line:         res.Node.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.mount to the Vault secrets engine path (e.g. 'secret' or 'kv')",
		})
	} else {
		// Mount should not start or end with /
		if strings.HasPrefix(mount, "/") || strings.HasSuffix(mount, "/") {
			findings = append(findings, Finding{
				RuleID:       "SV2060",
				Severity:     SeverityMedium,
				Message:      "VaultSecret spec.mount should not start or end with '/'",
				File:         res.File,
				Line:         mountLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("mount: %q — remove leading/trailing slashes", mount),
			})
		}
	}

	// path is required
	path, pathLine, pathOk := k8s.StringAt(m, "spec", "path")
	if !pathOk || path == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2060",
			Severity:     SeverityHigh,
			Message:      fmt.Sprintf("%s is missing spec.path — the Vault secret path is required", res.Kind),
			File:         res.File,
			Line:         res.Node.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.path to the Vault secret path within the mount (e.g. 'myapp/config')",
		})
	} else {
		// Check for template placeholders
		if strings.Contains(path, "{{") || strings.Contains(path, "${") {
			findings = append(findings, Finding{
				RuleID:       "SV2060",
				Severity:     SeverityMedium,
				Message:      "VaultSecret spec.path appears to contain an unexpanded template variable",
				File:         res.File,
				Line:         pathLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("path: %q", path),
			})
		}
		// Double slashes
		if strings.Contains(path, "//") {
			findings = append(findings, Finding{
				RuleID:       "SV2060",
				Severity:     SeverityMedium,
				Message:      "VaultSecret spec.path contains double slashes — possible typo",
				File:         res.File,
				Line:         pathLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("path: %q", path),
			})
		}
	}

	// destination.name is required
	destName, _, destOk := k8s.StringAt(m, "spec", "destination", "name")
	if !destOk || destName == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2060",
			Severity:     SeverityHigh,
			Message:      fmt.Sprintf("%s is missing spec.destination.name — target Secret name is required", res.Kind),
			File:         res.File,
			Line:         res.Node.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.destination.name to the name of the Kubernetes Secret to create",
		})
	}

	return findings
}
