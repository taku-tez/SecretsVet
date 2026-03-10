package clusterscan

import (
	"encoding/json"
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// SV4030 checks that Pods/Deployments set automountServiceAccountToken: false
// when they don't need API server access.
func checkSATokenMount(client *cluster.Client) []Finding {
	var findings []Finding

	// Check Pods
	podData, err := client.Get("pods")
	if err != nil {
		return append(findings, Finding{
			RuleID:   "SV4030",
			Severity: SeverityLow,
			Message:  "Could not retrieve pods for service account token check",
			Detail:   fmt.Sprintf("error: %v", err),
		})
	}

	type podMeta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type podSpecItem struct {
		AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
		ServiceAccountName           string `json:"serviceAccountName"`
	}
	type podItem struct {
		Metadata podMeta     `json:"metadata"`
		Spec     podSpecItem `json:"spec"`
	}

	items, err := cluster.ParseList(podData)
	if err != nil {
		return findings
	}

	for _, item := range items {
		var pod podItem
		if err := json.Unmarshal(item, &pod); err != nil {
			continue
		}
		// Skip system namespaces
		if isSystemNamespace(pod.Metadata.Namespace) {
			continue
		}
		// If automountServiceAccountToken is nil (not set) or true, flag it
		if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
			findings = append(findings, Finding{
				RuleID:       "SV4030",
				Severity:     SeverityMedium,
				Message:      "Pod does not set automountServiceAccountToken: false — service account token is automatically mounted",
				ResourceKind: "Pod",
				ResourceName: pod.Metadata.Name,
				Namespace:    pod.Metadata.Namespace,
				Detail:       fmt.Sprintf("serviceAccount: %s — if this pod doesn't need API access, set automountServiceAccountToken: false", pod.Spec.ServiceAccountName),
			})
		}
	}

	return findings
}

func isSystemNamespace(ns string) bool {
	systemNS := map[string]bool{
		"kube-system":    true,
		"kube-public":    true,
		"kube-node-lease": true,
	}
	return systemNS[ns]
}
