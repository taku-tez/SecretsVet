package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/gitscan"
	"github.com/SecretsVet/secretsvet/internal/output"
	"github.com/spf13/cobra"
)

var (
	gitMaxCommits  int
	gitSkipHistory bool
)

var gitScanCmd = &cobra.Command{
	Use:   "git-scan [path]",
	Short: "Scan git repository history for secrets",
	Long: `Scan a git repository's full commit history for secrets and misconfigurations.

Detects:
  - Secrets committed to any branch or tag (including deleted files)
  - .env / .env.* files ever committed
  - .gitignore missing patterns for secret file types
  - High-entropy strings in committed code
  - Secrets in Helm values.yaml files

Examples:
  secretsvet git-scan .
  secretsvet git-scan /path/to/repo --output json
  secretsvet git-scan . --max-commits 100`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitScan,
}

func init() {
	gitScanCmd.Flags().IntVar(&gitMaxCommits, "max-commits", 0, "Maximum number of commits to scan (0 = all)")
	gitScanCmd.Flags().BoolVar(&gitSkipHistory, "skip-history", false, "Skip commit history scan, only check .gitignore")
	rootCmd.AddCommand(gitScanCmd)
}

func runGitScan(cmd *cobra.Command, args []string) error {
	repoPath := "."
	if len(args) > 0 {
		repoPath = args[0]
	}

	result, err := gitscan.Scan(gitscan.ScanOptions{
		RepoPath:    repoPath,
		MaxCommits:  gitMaxCommits,
		SkipHistory: gitSkipHistory,
	})
	if err != nil {
		return fmt.Errorf("git-scan failed: %w", err)
	}

	switch strings.ToLower(outputFormat) {
	case "json":
		f := &output.GitJSONFormatter{}
		if err := f.WriteGit(os.Stdout, result); err != nil {
			return fmt.Errorf("output failed: %w", err)
		}
	default:
		f := &output.GitTTYFormatter{NoColor: noColor}
		if err := f.WriteGit(os.Stdout, result); err != nil {
			return fmt.Errorf("output failed: %w", err)
		}
	}

	if exitCode && len(result.Findings) > 0 {
		os.Exit(1)
	}

	return nil
}
