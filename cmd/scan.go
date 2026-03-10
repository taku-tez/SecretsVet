package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/output"
	"github.com/SecretsVet/secretsvet/internal/rule"
	"github.com/SecretsVet/secretsvet/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	recursive   bool
	kustomize   bool
	exitCode    bool
	minSeverity string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path...]",
	Short: "Scan YAML manifests for secret misconfigurations",
	Long: `Scan Kubernetes YAML manifests for secret misconfigurations.

Paths can be files or directories. When a directory is given, all .yaml/.yml
files within it are scanned. Use --recursive to scan subdirectories.

Examples:
  secretsvet scan ./manifests/
  secretsvet scan ./k8s/ --recursive
  secretsvet scan deploy.yaml --output json
  secretsvet scan ./k8s/ --kustomize --output sarif`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", true, "Recurse into subdirectories")
	scanCmd.Flags().BoolVarP(&kustomize, "kustomize", "k", false, "Run kustomize build on directories with kustomization.yaml")
	scanCmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit with code 1 if findings are found (useful in CI)")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "LOW", "Minimum severity to report: LOW, MEDIUM, HIGH")
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
		MinSeverity: minSev,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	var formatter output.Formatter
	switch strings.ToLower(outputFormat) {
	case "json":
		formatter = &output.JSONFormatter{}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	default:
		formatter = &output.TTYFormatter{NoColor: noColor}
	}

	if err := formatter.Write(os.Stdout, result); err != nil {
		return fmt.Errorf("output failed: %w", err)
	}

	if exitCode && len(result.Findings) > 0 {
		os.Exit(1)
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
