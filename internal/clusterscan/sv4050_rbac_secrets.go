package clusterscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// SV4050 detects RBAC roles that grant list/watch on Secrets.
// list/watch allows enumerating all secrets in a namespace or cluster.
func checkRBACSecretAccess(client *cluster.Client) []Finding {
	var findings []Finding

	for _, kind := range []string{"clusterroles", "roles"} {
		data, err := client.Get(kind)
		if err != nil {
			continue
		}

		type policyRule struct {
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
			Verbs     []string `json:"verbs"`
		}
		type roleMeta struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		}
		type roleItem struct {
			Metadata roleMeta     `json:"metadata"`
			Rules    []policyRule `json:"rules"`
		}

		items, err := cluster.ParseList(data)
		if err != nil {
			continue
		}

		for _, item := range items {
			var role roleItem
			if err := json.Unmarshal(item, &role); err != nil {
				continue
			}

			// Skip system roles
			if strings.HasPrefix(role.Metadata.Name, "system:") {
				continue
			}

			for _, rule := range role.Rules {
				if !coversSecrets(rule.Resources) {
					continue
				}

				dangerousVerbs := filterDangerousVerbs(rule.Verbs)
				if len(dangerousVerbs) == 0 {
					continue
				}

				resourceKind := "ClusterRole"
				if kind == "roles" {
					resourceKind = "Role"
				}

				severity := SeverityMedium
				if containsAny(dangerousVerbs, "list", "watch") {
					severity = SeverityHigh
				}

				findings = append(findings, Finding{
					RuleID:       "SV4050",
					Severity:     severity,
					Message:      fmt.Sprintf("%s grants dangerous verbs [%s] on Secrets", resourceKind, strings.Join(dangerousVerbs, ", ")),
					ResourceKind: resourceKind,
					ResourceName: role.Metadata.Name,
					Namespace:    role.Metadata.Namespace,
					Detail:       "list/watch on Secrets allows enumeration of all secret values in the namespace; restrict to 'get' on specific named resources",
				})
			}
		}
	}

	return findings
}

func coversSecrets(resources []string) bool {
	for _, r := range resources {
		if r == "secrets" || r == "*" {
			return true
		}
	}
	return false
}

func filterDangerousVerbs(verbs []string) []string {
	dangerous := map[string]bool{"list": true, "watch": true, "get": true, "*": true}
	var result []string
	for _, v := range verbs {
		if dangerous[v] {
			result = append(result, v)
		}
	}
	return result
}

func containsAny(slice []string, values ...string) bool {
	set := make(map[string]bool)
	for _, v := range values {
		set[v] = true
	}
	for _, s := range slice {
		if set[s] || s == "*" {
			return true
		}
	}
	return false
}
