package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/clusterscan"
	"github.com/SecretsVet/secretsvet/internal/output"
	"github.com/spf13/cobra"
)

var (
	clusterContext   string
	clusterNamespace string
	allNamespaces    bool
	skipEtcd         bool
	skipRuntime      bool
	skipRBAC         bool
)

var clusterScanCmd = &cobra.Command{
	Use:   "cluster-scan",
	Short: "Scan a live Kubernetes cluster for secret misconfigurations",
	Long: `Scan a running Kubernetes cluster for secret security issues.

Requires kubectl to be installed and configured with access to the target cluster.

Checks:
  - etcd encryption configuration (SV4010)
  - automountServiceAccountToken (SV4030)
  - Secret volume mounts without readOnly (SV4040)
  - RBAC roles with list/watch on Secrets (SV4050)
  - default ServiceAccount with Secret access (SV4060)

Examples:
  secretsvet cluster-scan
  secretsvet cluster-scan --context production --all-namespaces
  secretsvet cluster-scan --namespace myapp --output json
  secretsvet cluster-scan --skip-etcd --skip-rbac`,
	RunE: runClusterScan,
}

func init() {
	clusterScanCmd.Flags().StringVar(&clusterContext, "context", "", "Kubeconfig context name (default: current-context)")
	clusterScanCmd.Flags().StringVarP(&clusterNamespace, "namespace", "n", "", "Namespace to scan (default: current namespace)")
	clusterScanCmd.Flags().BoolVar(&allNamespaces, "all-namespaces", false, "Scan all namespaces")
	clusterScanCmd.Flags().BoolVar(&skipEtcd, "skip-etcd", false, "Skip etcd encryption checks")
	clusterScanCmd.Flags().BoolVar(&skipRuntime, "skip-runtime", false, "Skip runtime configuration checks")
	clusterScanCmd.Flags().BoolVar(&skipRBAC, "skip-rbac", false, "Skip RBAC checks")
	rootCmd.AddCommand(clusterScanCmd)
}

func runClusterScan(cmd *cobra.Command, args []string) error {
	result, err := clusterscan.Scan(clusterscan.ScanOptions{
		Context:       clusterContext,
		Namespace:     clusterNamespace,
		AllNamespaces: allNamespaces,
		SkipEtcd:      skipEtcd,
		SkipRuntime:   skipRuntime,
		SkipRBAC:      skipRBAC,
	})
	if err != nil {
		return fmt.Errorf("cluster-scan failed: %w", err)
	}

	switch strings.ToLower(outputFormat) {
	case "json":
		f := &output.ClusterJSONFormatter{}
		if err := f.Write(os.Stdout, result); err != nil {
			return fmt.Errorf("output failed: %w", err)
		}
	default:
		f := &output.ClusterTTYFormatter{NoColor: noColor}
		if err := f.Write(os.Stdout, result); err != nil {
			return fmt.Errorf("output failed: %w", err)
		}
	}

	if exitCode && len(result.Findings) > 0 {
		os.Exit(1)
	}

	return nil
}
