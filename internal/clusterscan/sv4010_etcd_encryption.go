package clusterscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// SV4010 checks whether etcd encryption is enabled for Secrets.
// It inspects the kube-apiserver pod's command arguments for
// --encryption-provider-config, then checks the EncryptionConfiguration
// to ensure 'identity' (no encryption) is not the first provider for secrets.
func checkEtcdEncryption(client *cluster.Client) []Finding {
	var findings []Finding

	// Strategy 1: Look at kube-apiserver pod for --encryption-provider-config flag
	apiserverData, err := client.GetAPIServerPod()
	if err != nil {
		findings = append(findings, Finding{
			RuleID:   "SV4010",
			Severity: SeverityLow,
			Message:  "Could not retrieve kube-apiserver pod spec — unable to verify etcd encryption configuration",
			Detail:   fmt.Sprintf("error: %v", err),
		})
		return findings
	}

	type container struct {
		Name    string   `json:"name"`
		Command []string `json:"command"`
	}
	type podSpec struct {
		Containers []container `json:"containers"`
	}
	type podItem struct {
		Spec podSpec `json:"spec"`
	}
	type podList struct {
		Items []podItem `json:"items"`
	}

	var list podList
	if err := json.Unmarshal(apiserverData, &list); err != nil || len(list.Items) == 0 {
		findings = append(findings, Finding{
			RuleID:   "SV4010",
			Severity: SeverityLow,
			Message:  "No kube-apiserver pod found — running in managed cluster or non-standard setup",
			Detail:   "Manual verification of etcd encryption is required",
		})
		return findings
	}

	encryptionConfigFound := false
	for _, item := range list.Items {
		for _, c := range item.Spec.Containers {
			if c.Name != "kube-apiserver" {
				continue
			}
			for _, arg := range c.Command {
				if strings.HasPrefix(arg, "--encryption-provider-config") {
					encryptionConfigFound = true
					break
				}
			}
		}
	}

	if !encryptionConfigFound {
		findings = append(findings, Finding{
			RuleID:   "SV4010",
			Severity: SeverityHigh,
			Message:  "kube-apiserver is not configured with --encryption-provider-config — Secrets are stored unencrypted in etcd",
			Detail:   "Add --encryption-provider-config to kube-apiserver and configure AES-CBC or AES-GCM encryption for Secrets",
		})
	}

	return findings
}

// checkEncryptionConfig inspects EncryptionConfiguration resources for 'identity' providers.
func checkEncryptionConfig(client *cluster.Client) []Finding {
	var findings []Finding

	data, err := client.GetEncryptionConfig()
	if err != nil {
		return nil // Not available in all clusters
	}

	// Generic JSON traversal for EncryptionConfiguration
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	items, _ := raw["items"].([]interface{})
	for _, item := range items {
		itemMap, _ := item.(map[string]interface{})
		spec, _ := itemMap["spec"].(map[string]interface{})
		resources, _ := spec["resources"].([]interface{})

		for _, res := range resources {
			resMap, _ := res.(map[string]interface{})
			resourceNames, _ := resMap["resources"].([]interface{})
			providers, _ := resMap["providers"].([]interface{})

			// Check if this resource entry covers secrets
			coversSecrets := false
			for _, r := range resourceNames {
				if rStr, ok := r.(string); ok && (rStr == "secrets" || rStr == "*") {
					coversSecrets = true
				}
			}
			if !coversSecrets {
				continue
			}

			// Check if 'identity' is the first provider (means no encryption)
			if len(providers) > 0 {
				firstProvider, _ := providers[0].(map[string]interface{})
				if _, hasIdentity := firstProvider["identity"]; hasIdentity {
					name, _ := itemMap["metadata"].(map[string]interface{})["name"].(string)
					findings = append(findings, Finding{
						RuleID:       "SV4010",
						Severity:     SeverityHigh,
						Message:      "EncryptionConfiguration has 'identity' as the first provider for Secrets — data is not encrypted at rest",
						ResourceKind: "EncryptionConfiguration",
						ResourceName: name,
						Detail:       "Move 'identity' to the last position and add an AES-CBC or AES-GCM provider as the first entry",
					})
				}
			}
		}
	}

	return findings
}
