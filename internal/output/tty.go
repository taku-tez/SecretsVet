package output

import (
	"fmt"
	"io"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
	"github.com/fatih/color"
)

// TTYFormatter writes human-readable colored output.
type TTYFormatter struct {
	NoColor bool
}

func (f *TTYFormatter) Write(w io.Writer, result *scanner.ScanResult) error {
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
		case rule.SeverityCritical:
			sev = critColor.Sprint("CRITICAL")
		case rule.SeverityHigh:
			sev = highColor.Sprint("HIGH    ")
		case rule.SeverityMedium:
			sev = medColor.Sprint("MEDIUM  ")
		case rule.SeverityLow:
			sev = lowColor.Sprint("LOW     ")
		}

		location := finding.File
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", finding.File, finding.Line)
		}

		resource := finding.ResourceKind
		if finding.ResourceName != "" {
			resource = fmt.Sprintf("%s/%s", finding.ResourceKind, finding.ResourceName)
		}
		if finding.Namespace != "" {
			resource = fmt.Sprintf("%s (ns: %s)", resource, finding.Namespace)
		}

		fmt.Fprintf(w, "[%s] %s  %s  %s\n", finding.RuleID, sev, location, resource)
		fmt.Fprintf(w, "        %s\n", finding.Message)
		if finding.Detail != "" {
			fmt.Fprintf(w, "        %s\n", color.New(color.Faint).Sprint(finding.Detail))
		}
		fmt.Fprintln(w)
	}

	critical, high, medium, low := result.Summary()
	total := critical + high + medium + low

	if total == 0 {
		color.New(color.FgGreen).Fprintln(w, "No findings. All checks passed.")
	} else {
		fmt.Fprintf(w, "Found %d finding(s) in %d resource(s) across %d file(s)\n",
			total, result.Resources, result.Files)
		fmt.Fprintf(w, "  %s  %s  %s  %s\n",
			critColor.Sprintf("CRITICAL: %d", critical),
			highColor.Sprintf("HIGH: %d", high),
			medColor.Sprintf("MEDIUM: %d", medium),
			lowColor.Sprintf("LOW: %d", low),
		)
	}

	return nil
}
