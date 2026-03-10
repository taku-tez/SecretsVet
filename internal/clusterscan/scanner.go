package clusterscan

import (
	"fmt"

	"github.com/SecretsVet/secretsvet/internal/cluster"
)

// ScanOptions controls the cluster scan.
type ScanOptions struct {
	Context       string
	Namespace     string
	AllNamespaces bool
	// Checks to run (nil = all)
	SkipEtcd    bool
	SkipRuntime bool
	SkipRBAC    bool
}

// Scan connects to the cluster and runs all checks.
func Scan(opts ScanOptions) (*ScanResult, error) {
	client := &cluster.Client{
		Context:       opts.Context,
		Namespace:     opts.Namespace,
		AllNamespaces: opts.AllNamespaces,
	}

	// Verify cluster is reachable
	if err := client.IsAvailable(); err != nil {
		return nil, fmt.Errorf("cluster not reachable: %w", err)
	}

	result := &ScanResult{Context: opts.Context}

	// etcd encryption checks
	if !opts.SkipEtcd {
		result.Findings = append(result.Findings, checkEtcdEncryption(client)...)
		result.Findings = append(result.Findings, checkEncryptionConfig(client)...)
	}

	// Runtime checks
	if !opts.SkipRuntime {
		result.Findings = append(result.Findings, checkSATokenMount(client)...)
		result.Findings = append(result.Findings, checkReadonlySecretMount(client)...)
	}

	// RBAC checks
	if !opts.SkipRBAC {
		result.Findings = append(result.Findings, checkRBACSecretAccess(client)...)
		result.Findings = append(result.Findings, checkDefaultSASecretAccess(client)...)
	}

	return result, nil
}
