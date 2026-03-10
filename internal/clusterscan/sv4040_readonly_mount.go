package clusterscan

import (
	"encoding/json"
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// SV4040 checks that Pods mounting Secrets use readOnly: true on the volume mount.
func checkReadonlySecretMount(client *cluster.Client) []Finding {
	var findings []Finding

	podData, err := client.Get("pods")
	if err != nil {
		return findings
	}

	type volumeMount struct {
		Name      string `json:"name"`
		ReadOnly  bool   `json:"readOnly"`
		MountPath string `json:"mountPath"`
	}
	type containerSpec struct {
		Name         string        `json:"name"`
		VolumeMounts []volumeMount `json:"volumeMounts"`
	}
	type volume struct {
		Name   string          `json:"name"`
		Secret json.RawMessage `json:"secret"`
	}
	type podMeta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type podSpecItem struct {
		Containers []containerSpec `json:"containers"`
		Volumes    []volume        `json:"volumes"`
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
		if isSystemNamespace(pod.Metadata.Namespace) {
			continue
		}

		// Build set of secret volume names
		secretVolumes := make(map[string]bool)
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil && string(vol.Secret) != "null" {
				secretVolumes[vol.Name] = true
			}
		}

		for _, c := range pod.Spec.Containers {
			for _, mount := range c.VolumeMounts {
				if !secretVolumes[mount.Name] {
					continue
				}
				if !mount.ReadOnly {
					findings = append(findings, Finding{
						RuleID:       "SV4040",
						Severity:     SeverityMedium,
						Message:      fmt.Sprintf("Container '%s' mounts Secret volume '%s' without readOnly: true", c.Name, mount.Name),
						ResourceKind: "Pod",
						ResourceName: pod.Metadata.Name,
						Namespace:    pod.Metadata.Namespace,
						Detail:       fmt.Sprintf("mountPath: %s — add readOnly: true to prevent accidental secret modification", mount.MountPath),
					})
				}
			}
		}
	}

	return findings
}
