package rule

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
	"gopkg.in/yaml.v3"
)

// SV2010 validates key references in ExternalSecret / ClusterExternalSecret.
// Checks that remoteRef.key is non-empty and uses a recognizable path format.
type esKeyRefRule struct{}

func NewESKeyRefRule() Rule { return &esKeyRefRule{} }
func (r *esKeyRefRule) ID() string { return "SV2010" }

func (r *esKeyRefRule) Check(res *k8s.Resource) []Finding {
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

	// spec.data[].remoteRef.key
	dataItems, ok := k8s.SequenceAt(m, "spec", "data")
	if ok {
		for _, item := range dataItems {
			if item.Kind != yaml.MappingNode {
				continue
			}
			findings = append(findings, checkRemoteRef(res, item)...)
		}
	}

	// spec.dataFrom[].extract.key or spec.dataFrom[].find.path
	dataFromItems, ok := k8s.SequenceAt(m, "spec", "dataFrom")
	if ok {
		for _, item := range dataFromItems {
			if item.Kind != yaml.MappingNode {
				continue
			}
			findings = append(findings, checkDataFrom(res, item)...)
		}
	}

	return findings
}

func checkRemoteRef(res *k8s.Resource, dataItem *yaml.Node) []Finding {
	var findings []Finding

	remoteRef, ok := k8s.NodeAt(dataItem, "remoteRef")
	if !ok || remoteRef == nil {
		// secretKey is present but remoteRef is missing
		secretKey, skLine, skOk := k8s.StringAt(dataItem, "secretKey")
		if skOk && secretKey != "" {
			findings = append(findings, Finding{
				RuleID:       "SV2010",
				Severity:     SeverityHigh,
				Message:      "ExternalSecret data entry has a secretKey but is missing remoteRef",
				File:         res.File,
				Line:         skLine,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       fmt.Sprintf("secretKey: %s", secretKey),
			})
		}
		return findings
	}

	key, keyLine, keyOk := k8s.StringAt(remoteRef, "key")
	if !keyOk || key == "" {
		findings = append(findings, Finding{
			RuleID:       "SV2010",
			Severity:     SeverityHigh,
			Message:      "ExternalSecret remoteRef.key is empty — secret path is not specified",
			File:         res.File,
			Line:         remoteRef.Line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       "set remoteRef.key to the path/name of the secret in the external store",
		})
		return findings
	}

	// Check for suspicious typo patterns in key paths
	if f := checkKeyTypo(res, key, keyLine, "remoteRef.key"); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func checkDataFrom(res *k8s.Resource, dataFromItem *yaml.Node) []Finding {
	var findings []Finding

	// Check extract.key
	if extractNode, ok := k8s.NodeAt(dataFromItem, "extract"); ok && extractNode != nil {
		key, keyLine, keyOk := k8s.StringAt(extractNode, "key")
		if !keyOk || key == "" {
			findings = append(findings, Finding{
				RuleID:       "SV2010",
				Severity:     SeverityHigh,
				Message:      "ExternalSecret dataFrom.extract.key is empty",
				File:         res.File,
				Line:         extractNode.Line,
				ResourceKind: res.Kind,
				ResourceName: res.Name,
				Namespace:    res.Namespace,
				Detail:       "set extract.key to the path/name of the secret",
			})
		} else if f := checkKeyTypo(res, key, keyLine, "dataFrom.extract.key"); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

// checkKeyTypo detects common path typos in secret key references.
func checkKeyTypo(res *k8s.Resource, key string, line int, field string) *Finding {
	// Double slashes in path
	if strings.Contains(key, "//") {
		return &Finding{
			RuleID:       "SV2010",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("ExternalSecret %s contains double slashes — possible typo in path", field),
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("%s: %q", field, key),
		}
	}

	// Trailing slash (invalid for most backends)
	if strings.HasSuffix(key, "/") {
		return &Finding{
			RuleID:       "SV2010",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("ExternalSecret %s has a trailing slash — possible typo", field),
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("%s: %q", field, key),
		}
	}

	// Looks like a template placeholder left unexpanded
	if strings.Contains(key, "{{") || strings.Contains(key, "${") {
		return &Finding{
			RuleID:       "SV2010",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("ExternalSecret %s appears to contain an unexpanded template variable", field),
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("%s: %q", field, key),
		}
	}

	return nil
}
