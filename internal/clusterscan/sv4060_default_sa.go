package clusterscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// SV4060 checks if the 'default' ServiceAccount has been granted Secret access
// via RoleBinding or ClusterRoleBinding.
func checkDefaultSASecretAccess(client *cluster.Client) []Finding {
	var findings []Finding

	for _, kind := range []string{"clusterrolebindings", "rolebindings"} {
		data, err := client.Get(kind)
		if err != nil {
			continue
		}

		type subject struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		}
		type roleRef struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		}
		type bindingMeta struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		}
		type binding struct {
			Metadata bindingMeta `json:"metadata"`
			Subjects []subject   `json:"subjects"`
			RoleRef  roleRef     `json:"roleRef"`
		}

		items, err := cluster.ParseList(data)
		if err != nil {
			continue
		}

		for _, item := range items {
			var b binding
			if err := json.Unmarshal(item, &b); err != nil {
				continue
			}

			// Skip system bindings
			if strings.HasPrefix(b.Metadata.Name, "system:") {
				continue
			}

			// Check if any subject is the default ServiceAccount
			for _, sub := range b.Subjects {
				if sub.Kind != "ServiceAccount" || sub.Name != "default" {
					continue
				}

				// This binding references the default SA
				// Now check if the roleRef involves Secret access
				// (We flag it and note that further verification is needed)
				resourceKind := "ClusterRoleBinding"
				if kind == "rolebindings" {
					resourceKind = "RoleBinding"
				}

				findings = append(findings, Finding{
					RuleID:       "SV4060",
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("%s '%s' grants role '%s' to the 'default' ServiceAccount", resourceKind, b.Metadata.Name, b.RoleRef.Name),
					ResourceKind: resourceKind,
					ResourceName: b.Metadata.Name,
					Namespace:    b.Metadata.Namespace,
					Detail:       fmt.Sprintf("default SA (ns: %s) is bound to %s '%s' — verify this role does not grant access to Secrets", sub.Namespace, b.RoleRef.Kind, b.RoleRef.Name),
				})
			}
		}
	}

	return findings
}
