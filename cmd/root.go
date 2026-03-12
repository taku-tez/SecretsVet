package cmd

import (
	"fmt"
	"os"

	"github.com/SecretsVet/secretsvet/internal/config"
	"github.com/SecretsVet/secretsvet/internal/version"
	"github.com/spf13/cobra"
)

var (
	outputFormat string
	noColor      bool
	configFile   string
	cfg          *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "secretsvet",
	Short: "Kubernetes secret misconfiguration scanner",
	Long: `SecretsVet detects plaintext secrets and misconfigurations in Kubernetes manifests.

It scans YAML files for:
  - Secrets embedded in env vars, args, and commands
  - Plaintext secrets in ConfigMaps
  - Secret resource misconfigurations
  - High-entropy strings that may be secrets`,
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.Version())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "tty", "Output format: tty, json, sarif, github-actions")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to config file (default: .secretsvet.yaml)")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = config.Load(configFile)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		return nil
	}
	rootCmd.AddCommand(versionCmd)
}
