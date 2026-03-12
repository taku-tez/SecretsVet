package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var rulesID string

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all detection rules",
	Long: `List all SecretsVet detection rules with their ID, severity, category, and description.

Examples:
  secretsvet rules                  # list all rules
  secretsvet rules --id SV1010      # show detailed info for one rule
  secretsvet rules --category git   # filter by category`,
	RunE: runRules,
}

var rulesCategory string

func init() {
	rulesCmd.Flags().StringVar(&rulesID, "id", "", "Show detailed information for a specific rule ID")
	rulesCmd.Flags().StringVar(&rulesCategory, "category", "", "Filter by category: manifest, external-secrets, git, cluster, helm-kustomize")
	rootCmd.AddCommand(rulesCmd)
}

func runRules(_ *cobra.Command, _ []string) error {
	// Show detail for a specific rule
	if rulesID != "" {
		return showRuleDetail(rulesID)
	}

	// List all rules (optionally filtered by category)
	return listRules(rulesCategory)
}

func listRules(filterCategory string) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tDESCRIPTION")
	fmt.Fprintln(w, "──────\t────────\t─────────────────\t──────────────────────────────────────────────────")

	for _, m := range rule.AllRules {
		if filterCategory != "" && string(m.Category) != filterCategory {
			continue
		}
		sevStr := colorSeverity(m.Severity)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ID, sevStr, string(m.Category), m.Short)
	}
	return w.Flush()
}

func showRuleDetail(id string) error {
	id = strings.ToUpper(id)
	m := rule.RuleMetadataByID(id)
	if m == nil {
		return fmt.Errorf("unknown rule ID: %q (run 'secretsvet rules' for a list)", id)
	}

	bold := color.New(color.Bold)
	bold.Printf("\n%s  ", m.ID)
	fmt.Printf("%s  [%s]\n", colorSeverity(m.Severity), string(m.Category))
	fmt.Printf("\n%s\n", m.Short)
	fmt.Printf("\n%s\n  %s\n", bold.Sprint("Description:"), wrapText(m.Description, 78, "  "))
	fmt.Printf("\n%s\n  %s\n", bold.Sprint("Remediation:"), wrapText(m.Remediation, 78, "  "))
	if m.Example != "" {
		fmt.Printf("\n%s\n", bold.Sprint("Example fix:"))
		for _, line := range strings.Split(m.Example, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Println()
	return nil
}

func colorSeverity(sev rule.Severity) string {
	if noColor {
		return string(sev)
	}
	switch sev {
	case rule.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint(string(sev))
	case rule.SeverityHigh:
		return color.New(color.FgRed).Sprint(string(sev))
	case rule.SeverityMedium:
		return color.New(color.FgYellow).Sprint(string(sev))
	case rule.SeverityLow:
		return color.New(color.FgCyan).Sprint(string(sev))
	}
	return string(sev)
}

// wrapText wraps text at maxWidth, prefixing continuation lines with indent.
func wrapText(text string, maxWidth int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) <= maxWidth {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = indent + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
