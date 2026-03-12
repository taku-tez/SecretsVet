package rule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/k8s"
)

// SV6020 detects Kustomize secretGenerator entries that reference .env files directly.
// Referencing .env files via secretGenerator.envs[] means the .env file must exist
// in the repository, risking plaintext secrets being committed.
type kustomizeSecretGenEnvRule struct{}

func NewKustomizeSecretGenEnvRule() Rule { return &kustomizeSecretGenEnvRule{} }
func (r *kustomizeSecretGenEnvRule) ID() string { return "SV6020" }

func (r *kustomizeSecretGenEnvRule) Check(res *k8s.Resource) []Finding {
	if res.Kind != "Kustomization" {
		return nil
	}
	m := res.MappingNode()
	if m == nil {
		return nil
	}

	secretGens, ok := k8s.SequenceAt(m, "secretGenerator")
	if !ok {
		return nil
	}

	var findings []Finding
	for _, gen := range secretGens {
		name, _, _ := k8s.StringAt(gen, "name")

		envFiles, ok := k8s.SequenceAt(gen, "envs")
		if !ok {
			// also check legacy "env" (singular)
			envFiles, ok = k8s.SequenceAt(gen, "env")
		}
		if ok {
			for _, envNode := range envFiles {
				envFile := envNode.Value
				base := filepath.Base(envFile)
				if isEnvFile(base) {
					severity := SeverityHigh
					msg := fmt.Sprintf("secretGenerator %q references .env file %q — plaintext secrets may be committed to the repository", name, envFile)
					findings = append(findings, Finding{
						RuleID:       "SV6020",
						Severity:     severity,
						Message:      msg,
						File:         res.File,
						Line:         envNode.Line,
						ResourceKind: res.Kind,
						ResourceName: res.Name,
						Namespace:    res.Namespace,
						Detail:       fmt.Sprintf("generator: %s, env file: %s", name, envFile),
					})
				}
			}
		}

		// Also flag "files" pointing to secret-looking files or using secret-looking key names
		files, ok := k8s.SequenceAt(gen, "files")
		if ok {
			for _, fileNode := range files {
				entry := fileNode.Value
				// entry may be "keyName=./path/to/file" or just "./path/to/file"
				keyPart := ""
				filePart := entry
				if idx := strings.Index(entry, "="); idx >= 0 {
					keyPart = entry[:idx]
					filePart = entry[idx+1:]
				}
				base := filepath.Base(filePart)
				if isEnvFile(base) || isSecretFile(base) || (keyPart != "" && isSecretFile(keyPart)) {
					findings = append(findings, Finding{
						RuleID:       "SV6020",
						Severity:     SeverityMedium,
						Message:      fmt.Sprintf("secretGenerator %q references a potentially sensitive file %q", name, entry),
						File:         res.File,
						Line:         fileNode.Line,
						ResourceKind: res.Kind,
						ResourceName: res.Name,
						Namespace:    res.Namespace,
						Detail:       fmt.Sprintf("generator: %s, file: %s", name, entry),
					})
				}
			}
		}
	}
	return findings
}

// isEnvFile returns true for .env, .env.local, .env.production, etc.
func isEnvFile(name string) bool {
	lower := strings.ToLower(name)
	return lower == ".env" ||
		strings.HasPrefix(lower, ".env.") ||
		strings.HasSuffix(lower, ".env") ||
		lower == "dotenv"
}

// isSecretFile returns true for files that likely contain secrets.
func isSecretFile(name string) bool {
	lower := strings.ToLower(name)
	suspicious := []string{"secret", "password", "credential", "private_key", "privatekey"}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
