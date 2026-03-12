package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/baseline"
	"github.com/SecretsVet/secretsvet/internal/fixer"
	"github.com/SecretsVet/secretsvet/internal/output"
	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	recursive     bool
	kustomize     bool
	exitCode      bool
	minSeverity   string
	fixMode       bool
	fixLang       string
	fixLLM        bool
	helmCharts    []string
	baselineFile  string
	saveBaseline  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path...]",
	Short: "Scan YAML manifests for secret misconfigurations",
	Long: `Scan Kubernetes YAML manifests for secret misconfigurations.

Paths can be files, directories, or "-" to read from stdin.
When a directory is given, all .yaml/.yml files within it are scanned.
Use --recursive to scan subdirectories.

Examples:
  secretsvet scan ./manifests/
  secretsvet scan ./k8s/ --recursive
  secretsvet scan deploy.yaml --output json
  secretsvet scan ./k8s/ --kustomize --output sarif
  helm template ./mychart | secretsvet scan -
  kustomize build ./overlays/prod | secretsvet scan -`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", true, "Recurse into subdirectories")
	scanCmd.Flags().BoolVarP(&kustomize, "kustomize", "k", false, "Run kustomize build on directories with kustomization.yaml")
	scanCmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit with code 1 if findings are found (useful in CI)")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "LOW", "Minimum severity to report: LOW, MEDIUM, HIGH")
	scanCmd.Flags().BoolVar(&fixMode, "fix", false, "Generate fix suggestions for each finding")
	scanCmd.Flags().StringVar(&fixLang, "fix-lang", "en", "Language for fix explanations: en, ja")
	scanCmd.Flags().BoolVar(&fixLLM, "fix-llm", false, "Use Claude API for fix suggestions when no static template exists (requires ANTHROPIC_API_KEY)")
	scanCmd.Flags().StringArrayVar(&helmCharts, "helm", nil, "Run 'helm template <dir>' and scan the output (can be specified multiple times)")
	scanCmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to baseline file — only report findings not present in the baseline")
	scanCmd.Flags().StringVar(&saveBaseline, "save-baseline", "", "Save current findings to this file as a new baseline")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	minSev, err := parseSeverity(minSeverity)
	if err != nil {
		return err
	}

	result, err := scanner.Scan(scanner.ScanOptions{
		Paths:       args,
		Recursive:   recursive,
		Kustomize:   kustomize,
		HelmCharts:  helmCharts,
		MinSeverity: minSev,
		Config:      cfg,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Save baseline before filtering (captures all current findings)
	if saveBaseline != "" {
		if err := baseline.Save(saveBaseline, result.Findings); err != nil {
			return fmt.Errorf("save baseline: %w", err)
		}
		fmt.Fprintf(os.Stderr, "baseline saved: %s (%d findings)\n", saveBaseline, len(result.Findings))
	}

	// Apply baseline: suppress known findings
	if baselineFile != "" {
		bl, err := baseline.Load(baselineFile)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		before := len(result.Findings)
		result.Findings = baseline.Filter(result.Findings, bl)
		suppressed := before - len(result.Findings)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "baseline: suppressed %d known finding(s), %d new\n", suppressed, len(result.Findings))
		}
	}

	var formatter output.Formatter
	switch strings.ToLower(outputFormat) {
	case "json":
		formatter = &output.JSONFormatter{}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	case "github-actions":
		formatter = &output.GitHubActionsFormatter{}
	default:
		formatter = &output.TTYFormatter{NoColor: noColor}
	}

	if err := formatter.Write(os.Stdout, result); err != nil {
		return fmt.Errorf("output failed: %w", err)
	}

	// Generate fix suggestions if requested
	if fixMode && len(result.Findings) > 0 {
		if err := printFixSuggestions(result.Findings, fixLang, fixLLM); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fix generation failed: %v\n", err)
		}
	}

	if exitCode && len(result.Findings) > 0 {
		os.Exit(1)
	}

	return nil
}

func printFixSuggestions(findings []rule.Finding, lang string, useLLM bool) error {
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if lang == "ja" {
		fmt.Println("  修正提案")
	} else {
		fmt.Println("  Fix Suggestions")
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Deduplicate by ruleID so we don't repeat the same fix for many findings
	shownRules := make(map[string]bool)

	for _, finding := range findings {
		if shownRules[finding.RuleID] {
			continue
		}

		fix, err := fixer.GenerateFix(finding, lang, useLLM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: fix for %s: %v\n", finding.RuleID, err)
			continue
		}
		if fix == nil {
			continue
		}

		shownRules[finding.RuleID] = true

		fmt.Printf("\n[%s] %s\n", fix.RuleID, fix.Severity)
		if fix.Problem != "" {
			if lang == "ja" {
				fmt.Printf("問題: %s\n", fix.Problem)
			} else {
				fmt.Printf("Problem:  %s\n", fix.Problem)
			}
		}
		if fix.Solution != "" {
			if lang == "ja" {
				fmt.Printf("解決策: %s\n", fix.Solution)
			} else {
				fmt.Printf("Solution: %s\n", fix.Solution)
			}
		}
		if fix.YAMLSnippet != "" {
			fmt.Println()
			for _, line := range strings.Split(fix.YAMLSnippet, "\n") {
				fmt.Printf("  %s\n", line)
			}
		}
		if fix.Source == "llm" {
			fmt.Printf("\n  [Generated by Claude API]\n")
		}
		fmt.Println()
	}

	return nil
}

func parseSeverity(s string) (rule.Severity, error) {
	switch strings.ToUpper(s) {
	case "HIGH":
		return rule.SeverityHigh, nil
	case "MEDIUM":
		return rule.SeverityMedium, nil
	case "LOW":
		return rule.SeverityLow, nil
	default:
		return rule.SeverityLow, fmt.Errorf("invalid severity: %q (must be LOW, MEDIUM, or HIGH)", s)
	}
}
