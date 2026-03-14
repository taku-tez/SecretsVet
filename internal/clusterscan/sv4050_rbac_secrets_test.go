package clusterscan

import (
	"encoding/json"
	"testing"
)

// buildClusterRoleJSON returns a minimal ClusterRole JSON for table-driven tests.
func buildClusterRoleJSON(name string, labels map[string]string, resources, verbs []string) json.RawMessage {
	type policyRule struct {
		APIGroups []string `json:"apiGroups"`
		Resources []string `json:"resources"`
		Verbs     []string `json:"verbs"`
	}
	type meta struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels,omitempty"`
	}
	type clusterRole struct {
		APIVersion string       `json:"apiVersion"`
		Kind       string       `json:"kind"`
		Metadata   meta         `json:"metadata"`
		Rules      []policyRule `json:"rules"`
	}

	cr := clusterRole{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRole",
		Metadata:   meta{Name: name, Labels: labels},
		Rules: []policyRule{
			{APIGroups: []string{""}, Resources: resources, Verbs: verbs},
		},
	}
	b, _ := json.Marshal(cr)
	return b
}

// buildRoleJSON returns a minimal Role JSON for table-driven tests.
func buildRoleJSON(name, namespace string, resources, verbs []string) json.RawMessage {
	type policyRule struct {
		APIGroups []string `json:"apiGroups"`
		Resources []string `json:"resources"`
		Verbs     []string `json:"verbs"`
	}
	type meta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type role struct {
		APIVersion string       `json:"apiVersion"`
		Kind       string       `json:"kind"`
		Metadata   meta         `json:"metadata"`
		Rules      []policyRule `json:"rules"`
	}

	r := role{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "Role",
		Metadata:   meta{Name: name, Namespace: namespace},
		Rules: []policyRule{
			{APIGroups: []string{""}, Resources: resources, Verbs: verbs},
		},
	}
	b, _ := json.Marshal(r)
	return b
}

func TestIsSystemClusterRole(t *testing.T) {
	cases := []struct {
		name       string
		roleName   string
		labels     map[string]string
		namespace  string
		kind       string // "clusterroles" or "roles"
		resources  []string
		verbs      []string
		wantFinds  int
	}{
		{
			name:      "system: prefix is skipped",
			roleName:  "system:node",
			kind:      "clusterroles",
			resources: []string{"secrets"},
			verbs:     []string{"list", "watch"},
			wantFinds: 0,
		},
		{
			name:      "cluster-admin is skipped",
			roleName:  "cluster-admin",
			kind:      "clusterroles",
			resources: []string{"*"},
			verbs:     []string{"*"},
			wantFinds: 0,
		},
		{
			name:      "admin is skipped",
			roleName:  "admin",
			kind:      "clusterroles",
			resources: []string{"secrets"},
			verbs:     []string{"list"},
			wantFinds: 0,
		},
		{
			name:      "edit is skipped",
			roleName:  "edit",
			kind:      "clusterroles",
			resources: []string{"secrets"},
			verbs:     []string{"get"},
			wantFinds: 0,
		},
		{
			name:      "view is skipped",
			roleName:  "view",
			kind:      "clusterroles",
			resources: []string{"secrets"},
			verbs:     []string{"list"},
			wantFinds: 0,
		},
		{
			name:     "bootstrapping label is skipped",
			roleName: "kubeadm:get-nodes",
			kind:     "clusterroles",
			labels:   map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"},
			resources: []string{"secrets"},
			verbs:     []string{"list"},
			wantFinds: 0,
		},
		{
			name:      "Role in kube-system is skipped",
			roleName:  "extension-apiserver-authentication-reader",
			namespace: "kube-system",
			kind:      "roles",
			resources: []string{"secrets"},
			verbs:     []string{"get", "list"},
			wantFinds: 0,
		},
		{
			name:      "Role in kube-public is skipped",
			roleName:  "custom-role",
			namespace: "kube-public",
			kind:      "roles",
			resources: []string{"secrets"},
			verbs:     []string{"list"},
			wantFinds: 0,
		},
		{
			name:      "user-defined ClusterRole with list+watch on secrets is flagged",
			roleName:  "app-secret-reader",
			kind:      "clusterroles",
			resources: []string{"secrets"},
			verbs:     []string{"list", "watch"},
			wantFinds: 1,
		},
		{
			name:      "user-defined Role in default namespace is flagged",
			roleName:  "secret-lister",
			namespace: "default",
			kind:      "roles",
			resources: []string{"secrets"},
			verbs:     []string{"list"},
			wantFinds: 1,
		},
		{
			name:      "non-secrets resource is not flagged",
			roleName:  "pod-reader",
			kind:      "clusterroles",
			resources: []string{"pods"},
			verbs:     []string{"list", "watch"},
			wantFinds: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.kind == "clusterroles" {
				raw = buildClusterRoleJSON(tc.roleName, tc.labels, tc.resources, tc.verbs)
			} else {
				raw = buildRoleJSON(tc.roleName, tc.namespace, tc.resources, tc.verbs)
			}

			findings := applyRBACCheck(tc.kind, []json.RawMessage{raw})
			if len(findings) != tc.wantFinds {
				t.Errorf("got %d findings, want %d (role=%q kind=%s)", len(findings), tc.wantFinds, tc.roleName, tc.kind)
			}
		})
	}
}
