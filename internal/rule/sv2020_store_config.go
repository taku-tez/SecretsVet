package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2020 validates SecretStore / ClusterSecretStore connection configuration.
type storeConfigRule struct{}

func NewStoreConfigRule() Rule { return &storeConfigRule{} }
func (r *storeConfigRule) ID() string { return "SV2020" }

func (r *storeConfigRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "SecretStore", "ClusterSecretStore":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	providerNode, ok := k8s.NodeAt(m, "spec", "provider")
	if !ok || providerNode == nil || providerNode.Kind != yaml.MappingNode {
		return []Finding{{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      fmt.Sprintf("%s is missing spec.provider — no backend configured", res.Kind),
			File:         res.File,
			Line:         res.Node.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
		}}
	}

	var findings []Finding
	findings = append(findings, checkAWSProvider(res, providerNode)...)
	findings = append(findings, checkGCPProvider(res, providerNode)...)
	findings = append(findings, checkVaultProvider(res, providerNode)...)

	return findings
}

func checkAWSProvider(res *k8s.Resource, provider *yaml.Node) []Finding {
	awsNode, ok := k8s.NodeAt(provider, "aws")
	if !ok || awsNode == nil {
		return nil
	}

	var findings []Finding

	// region is required for AWS
	region, _, regionOk := k8s.StringAt(awsNode, "region")
	if !regionOk || region == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore AWS provider is missing spec.provider.aws.region",
			File:         res.File,
			Line:         awsNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.provider.aws.region (e.g. us-east-1)",
		})
	}

	// service must be SecretsManager or ParameterStore
	service, serviceLine, serviceOk := k8s.StringAt(awsNode, "service")
	if !serviceOk || service == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore AWS provider is missing spec.provider.aws.service",
			File:         res.File,
			Line:         awsNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.provider.aws.service to 'SecretsManager' or 'ParameterStore'",
		})
	} else if service != "SecretsManager" && service != "ParameterStore" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("SecretStore AWS provider has unrecognized service: %q", service),
			File:         res.File,
			Line:         serviceLine,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "expected 'SecretsManager' or 'ParameterStore'",
		})
	}

	return findings
}

func checkGCPProvider(res *k8s.Resource, provider *yaml.Node) []Finding {
	gcpNode, ok := k8s.NodeAt(provider, "gcpsm")
	if !ok || gcpNode == nil {
		return nil
	}

	var findings []Finding

	// projectID is required
	projectID, _, projectOk := k8s.StringAt(gcpNode, "projectID")
	if !projectOk || projectID == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore GCP Secret Manager provider is missing spec.provider.gcpsm.projectID",
			File:         res.File,
			Line:         gcpNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.provider.gcpsm.projectID to your GCP project ID",
		})
	}

	return findings
}

func checkVaultProvider(res *k8s.Resource, provider *yaml.Node) []Finding {
	vaultNode, ok := k8s.NodeAt(provider, "vault")
	if !ok || vaultNode == nil {
		return nil
	}

	var findings []Finding

	// server URL is required
	server, _, serverOk := k8s.StringAt(vaultNode, "server")
	if !serverOk || server == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore Vault provider is missing spec.provider.vault.server",
			File:         res.File,
			Line:         vaultNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.provider.vault.server to the Vault server URL",
		})
	}

	// path is required
	path, _, pathOk := k8s.StringAt(vaultNode, "path")
	if !pathOk || path == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore Vault provider is missing spec.provider.vault.path",
			File:         res.File,
			Line:         vaultNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set spec.provider.vault.path to the KV secrets mount path",
		})
	}

	// auth is required
	if _, hasAuth := k8s.NodeAt(vaultNode, "auth"); !hasAuth {
		findings = append(findings, Finding{
			RuleID:       "SV2020",
			Severity:     SeverityHigh,
			Message:      "SecretStore Vault provider is missing spec.provider.vault.auth",
			File:         res.File,
			Line:         vaultNode.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "configure vault.auth (kubernetes, token, appRole, etc.)",
		})
	}

	return findings
}
