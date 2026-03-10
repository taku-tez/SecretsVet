package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/clusterscan"
	"github.com/fatih/color"
)

// ClusterTTYFormatter writes human-readable colored output for cluster scan results.
type ClusterTTYFormatter struct {
	NoColor bool
}

func (f *ClusterTTYFormatter) Write(w io.Writer, result *clusterscan.ScanResult) error {
	if f.NoColor {
		color.NoColor = true
	}

	critColor := color.New(color.FgRed, color.Bold, color.BgRed)
	highColor := color.New(color.FgRed, color.Bold)
	medColor := color.New(color.FgYellow)
	lowColor := color.New(color.FgCyan)

	for _, finding := range result.Findings {
		var sev string
		switch finding.Severity {
		case clusterscan.SeverityCritical:
			sev = critColor.Sprint("CRITICAL")
		case clusterscan.SeverityHigh:
			sev = highColor.Sprint("HIGH    ")
		case clusterscan.SeverityMedium:
			sev = medColor.Sprint("MEDIUM  ")
		case clusterscan.SeverityLow:
			sev = lowColor.Sprint("LOW     ")
		}

		resource := finding.ResourceKind
		if finding.ResourceName != "" {
			resource = fmt.Sprintf("%s/%s", finding.ResourceKind, finding.ResourceName)
		}
		if finding.Namespace != "" {
			resource = fmt.Sprintf("%s (ns: %s)", resource, finding.Namespace)
		}
		if resource == "" {
			resource = "cluster"
		}

		fmt.Fprintf(w, "[%s] %s  %s\n", finding.RuleID, sev, resource)
		fmt.Fprintf(w, "        %s\n", finding.Message)
		if finding.Detail != "" {
			fmt.Fprintf(w, "        %s\n", color.New(color.Faint).Sprint(finding.Detail))
		}
		fmt.Fprintln(w)
	}

	critical, high, medium, low := result.Summary()
	total := critical + high + medium + low

	ctx := result.Context
	if ctx == "" {
		ctx = "current-context"
	}

	if total == 0 {
		color.New(color.FgGreen).Fprintf(w, "No findings in cluster [%s].\n", ctx)
	} else {
		fmt.Fprintf(w, "Found %d finding(s) in cluster [%s]\n", total, ctx)
		fmt.Fprintf(w, "  %s  %s  %s  %s\n",
			critColor.Sprintf("CRITICAL: %d", critical),
			highColor.Sprintf("HIGH: %d", high),
			medColor.Sprintf("MEDIUM: %d", medium),
			lowColor.Sprintf("LOW: %d", low),
		)
	}

	return nil
}

// ClusterJSONFormatter writes JSON output for cluster scan results.
type ClusterJSONFormatter struct{}

type clusterJSONFinding struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	ResourceKind string `json:"resource_kind,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type clusterJSONSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type clusterJSONOutput struct {
	Context  string               `json:"context"`
	Summary  clusterJSONSummary   `json:"summary"`
	Findings []clusterJSONFinding `json:"findings"`
}

func (f *ClusterJSONFormatter) Write(w io.Writer, result *clusterscan.ScanResult) error {
	critical, high, medium, low := result.Summary()
	out := clusterJSONOutput{
		Context: result.Context,
		Summary: clusterJSONSummary{
			Total:    critical + high + medium + low,
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
		},
	}
	for _, finding := range result.Findings {
		out.Findings = append(out.Findings, clusterJSONFinding{
			RuleID:       finding.RuleID,
			Severity:     strings.ToLower(string(finding.Severity)),
			Message:      finding.Message,
			ResourceKind: finding.ResourceKind,
			ResourceName: finding.ResourceName,
			Namespace:    finding.Namespace,
			Detail:       finding.Detail,
		})
	}
	if out.Findings == nil {
		out.Findings = []clusterJSONFinding{}
	}
	return jsonEncoder(w).Encode(out)
}
