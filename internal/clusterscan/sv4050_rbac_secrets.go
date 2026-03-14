package clusterscan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// systemClusterRoles lists Kubernetes built-in aggregated ClusterRoles that are
// part of normal cluster operation and should not generate SV4050 findings.
var systemClusterRoles = map[string]bool{
	"cluster-admin": true,
	"admin":         true,
	"edit":          true,
	"view":          true,
}

// systemNamespaces lists namespaces whose Roles are managed by Kubernetes or
// cluster add-ons and are not user-controlled.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

type rbacPolicyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type rbacRoleMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type rbacRoleItem struct {
	Metadata rbacRoleMeta     `json:"metadata"`
	Rules    []rbacPolicyRule `json:"rules"`
}

// applyRBACCheck processes a slice of raw JSON role items for a given kind
// ("clusterroles" or "roles") and returns SV4050 findings.
// Extracted for testability.
func applyRBACCheck(kind string, items []json.RawMessage) []Finding {
	var findings []Finding

	for _, item := range items {
		var role rbacRoleItem
		if err := json.Unmarshal(item, &role); err != nil {
			continue
		}

		// Skip roles with system: prefix (Kubernetes internal roles)
		if strings.HasPrefix(role.Metadata.Name, "system:") {
			continue
		}

		// Skip well-known built-in aggregated ClusterRoles
		if systemClusterRoles[role.Metadata.Name] {
			continue
		}

		// Skip roles managed by Kubernetes bootstrapping (e.g. kubeadm)
		if role.Metadata.Labels["kubernetes.io/bootstrapping"] != "" {
			continue
		}

		// Skip Roles in system-managed namespaces
		if kind == "roles" && systemNamespaces[role.Metadata.Namespace] {
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

	return findings
}

// SV4050 detects RBAC roles that grant list/watch on Secrets.
// list/watch allows enumerating all secrets in a namespace or cluster.
func checkRBACSecretAccess(client *cluster.Client) []Finding {
	var findings []Finding

	for _, kind := range []string{"clusterroles", "roles"} {
		data, err := client.Get(kind)
		if err != nil {
			continue
		}

		items, err := cluster.ParseList(data)
		if err != nil {
			continue
		}

		findings = append(findings, applyRBACCheck(kind, items)...)
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
