package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV6040 warns when a Kubernetes Secret is directly managed by Helm.
// Helm-managed Secrets imply the secret values originate from values.yaml or
// --set flags, both of which can easily expose secrets in git history or CI logs.
type helmManagedSecretRule struct{}

func NewHelmManagedSecretRule() Rule { return &helmManagedSecretRule{} }
func (r *helmManagedSecretRule) ID() string { return "SV6040" }

func (r *helmManagedSecretRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "Secret" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	// Check for Helm management label: app.kubernetes.io/managed-by: Helm
	managedBy, line, ok := k8s.StringAt(m, "metadata", "labels", "app.kubernetes.io/managed-by")
	if ok && managedBy == "Helm" {
		releaseName, _, _ := k8s.StringAt(m, "metadata", "annotations", "meta.helm.sh/release-name")
		detail := "Secret is managed by Helm — values originate from values.yaml or --set flags"
		if releaseName != "" {
			detail = fmt.Sprintf("Helm release: %s — values originate from values.yaml or --set flags", releaseName)
		}
		return []Finding{{
			RuleID:       "SV6040",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("Secret %q is directly managed by Helm, risking secret exposure via values.yaml or --set in CI logs", res.Name),
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       detail,
		}}
	}

	// Also check annotation: meta.helm.sh/release-name
	if _, annLine, hasAnno := k8s.StringAt(m, "metadata", "annotations", "meta.helm.sh/release-name"); hasAnno {
		releaseName, _, _ := k8s.StringAt(m, "metadata", "annotations", "meta.helm.sh/release-name")
		return []Finding{{
			RuleID:       "SV6040",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("Secret %q is directly managed by Helm (release: %s), risking secret exposure via values.yaml or --set in CI logs", res.Name, releaseName),
			File:         res.File,
			Line:         annLine,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("Helm release: %s — use External Secrets Operator or Helm Secrets plugin instead", releaseName),
		}}
	}

	return nil
}
