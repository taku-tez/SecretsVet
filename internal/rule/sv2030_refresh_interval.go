package rule

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV2030 warns when refreshInterval is set to more than 24 hours.
// A long refresh interval means secrets may take a long time to rotate.
type refreshIntervalRule struct{}

func NewRefreshIntervalRule() Rule { return &refreshIntervalRule{} }
func (r *refreshIntervalRule) ID() string { return "SV2030" }

// maxRefreshHours is the threshold above which we warn.
const maxRefreshHours = 24

func (r *refreshIntervalRule) Check(res *k8s.Resource) []Finding {
	switch res.Kind {
	case "ExternalSecret", "ClusterExternalSecret":
	default:
		return nil
	}

	m := res.MappingNode()
	if m == nil {
		return nil
	}

	interval, line, ok := k8s.StringAt(m, "spec", "refreshInterval")
	if !ok || interval == "" {
		// ESO default is 1h, which is fine. No finding.
		return nil
	}

	hours, err := parseDurationHours(interval)
	if err != nil {
		// Can't parse, skip
		return nil
	}

	if hours > maxRefreshHours {
		return []Finding{{
			RuleID:       "SV2030",
			Severity:     SeverityMedium,
			Message:      fmt.Sprintf("ExternalSecret refreshInterval is %s (%.0fh) — values over 24h delay secret rotation", interval, hours),
			File:         res.File,
			Line:         line,
			ResourceKind: res.Kind,
			ResourceName: res.Name,
			Namespace:    res.Namespace,
			Detail:       fmt.Sprintf("current: %s, recommended: ≤24h (e.g. '1h')", interval),
		}}
	}

	return nil
}

// parseDurationHours converts a Go/Kubernetes duration string to hours.
// Supports: h, m, s, d suffixes and combinations like "48h30m".
var durationRe = regexp.MustCompile(`(\d+)(d|h|m|s)`)

func parseDurationHours(s string) (float64, error) {
	matches := durationRe.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("unrecognized duration: %s", s)
	}
	var totalHours float64
	for _, m := range matches {
		val, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, err
		}
		switch m[2] {
		case "d":
			totalHours += val * 24
		case "h":
			totalHours += val
		case "m":
			totalHours += val / 60
		case "s":
			totalHours += val / 3600
		}
	}
	return totalHours, nil
}
