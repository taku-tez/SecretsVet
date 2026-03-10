package rule

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2100 checks whether auto-rotation is configured in ExternalSecret resources.
// ESO doesn't rotate by itself, but refreshInterval=0 (disabled) is a common mistake.
// For AWS/GCP stores it checks for rotation-related annotations.
type rotationRule struct{}

func NewRotationRule() Rule { return &rotationRule{} }
func (r *rotationRule) ID() string { return "SV2100" }

func (r *rotationRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "ExternalSecret", "ClusterExternalSecret":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	var findings []Finding

	// refreshInterval: "0" disables auto-refresh (effectively disables rotation)
	interval, line, ok := k8s.StringAt(m, "spec", "refreshInterval")
	if ok && (interval == "0" || interval == "0s" || interval == "0h" || interval == "0m") {
		findings = append(findings, Finding{
			RuleID:       "SV2100",
			Severity:     SeverityMedium,
			Message:      "ExternalSecret has refreshInterval: 0 — automatic secret refresh is disabled",
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set a non-zero refreshInterval to enable automatic rotation (e.g. '1h')",
		})
	}

	// Check if all remoteRef entries have a version pinned (no rotation possible)
	dataItems, ok := k8s.SequenceAt(m, "spec", "data")
	if ok {
		allVersionPinned := true
		anyData := false
		for _, item := range dataItems {
			if item.Kind != yaml.MappingNode {
				continue
			}
			anyData = true
			_, _, versionOk := k8s.StringAt(item, "remoteRef", "version")
			if !versionOk {
				allVersionPinned = false
				break
			}
		}
		if anyData && allVersionPinned {
			findings = append(findings, Finding{
				RuleID:       "SV2100",
				Severity:     SeverityLow,
				Message:      "All ExternalSecret remoteRef entries pin a specific version — secrets will not auto-rotate when the backend version changes",
				File:         res.File,
				Line:         0,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("remove remoteRef.version to track the 'latest' version, or document why pinning is required"),
			})
		}
	}

	return findings
}
