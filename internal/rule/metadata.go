package rule

// Category classifies rules by the layer they operate on.
type Category string

const (
	CategoryManifest        Category = "manifest"
	CategoryExternalSecrets Category = "external-secrets"
	CategoryGit             Category = "git"
	CategoryCluster         Category = "cluster"
	CategoryHelmKustomize   Category = "helm-kustomize"
)

// RuleMetadata holds human-readable information about a rule.
type RuleMetadata struct {
	ID          string
	Severity    Severity
	Category    Category
	Short       string // one-line description
	Description string // detailed explanation
	Remediation string // how to fix
	Example     string // YAML example of the fix (optional)
}

// AllRules is the complete metadata catalog, ordered by rule ID.
var AllRules = []RuleMetadata{
	// ── v0.1.0 Static manifest detection ─────────────────────────────────────
	{
		ID:          "SV1010",
		Severity:    SeverityHigh,
		Category:    CategoryManifest,
		Short:       "Plaintext secret pattern in env[].value",
		Description: "Detects known secret patterns (AWS keys, GitHub tokens, Stripe keys, etc.) hardcoded in env[].value fields of Pod/Deployment/StatefulSet/Job specs.",
		Remediation: "Move the secret to a Kubernetes Secret resource and reference it via valueFrom.secretKeyRef.",
		Example: `env:
  - name: AWS_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: aws-secrets
        key: secret-access-key`,
	},
	{
		ID:          "SV1020",
		Severity:    SeverityMedium,
		Category:    CategoryManifest,
		Short:       "High-entropy string in env[].value (possible secret)",
		Description: "Uses Shannon entropy analysis to detect probable secrets that don't match known patterns. High-entropy strings in env vars often indicate API keys or tokens.",
		Remediation: "If this is a secret, move it to a Kubernetes Secret resource and use valueFrom.secretKeyRef.",
	},
	{
		ID:          "SV1030",
		Severity:    SeverityHigh,
		Category:    CategoryManifest,
		Short:       "Secret embedded in container args[] or command[]",
		Description: "Detects secret patterns or suspicious values passed directly in args[] or command[] arrays. These are visible in pod specs and process listings.",
		Remediation: "Pass secrets as environment variables sourced from a Kubernetes Secret.",
		Example: `# Use env var reference instead:
args:
  - "--api-key=$(API_KEY)"
env:
  - name: API_KEY
    valueFrom:
      secretKeyRef:
        name: my-secrets
        key: api-key`,
	},
	{
		ID:          "SV1040",
		Severity:    SeverityHigh,
		Category:    CategoryManifest,
		Short:       "Plaintext secret in ConfigMap data",
		Description: "ConfigMaps are not encrypted at rest (even when etcd encryption is configured). Storing secrets in ConfigMaps bypasses Kubernetes RBAC controls for Secret resources.",
		Remediation: "Move sensitive values to a Kubernetes Secret resource.",
	},
	{
		ID:          "SV1050",
		Severity:    SeverityLow,
		Category:    CategoryManifest,
		Short:       "envFrom references a ConfigMap (not a Secret)",
		Description: "envFrom with configMapRef loads all keys as environment variables. If the ConfigMap contains sensitive data, it will not be encrypted at rest.",
		Remediation: "If the ConfigMap contains sensitive values, migrate them to a Secret and use secretRef instead.",
	},
	{
		ID:          "SV1060",
		Severity:    SeverityHigh,
		Category:    CategoryManifest,
		Short:       "Secret data contains a known secret pattern (after base64 decode)",
		Description: "Decodes base64-encoded Secret data fields and checks the decoded value against known secret patterns. Confirms the Secret actually holds sensitive data.",
		Remediation: "Use External Secrets Operator or Sealed Secrets to avoid storing secrets in manifests.",
	},
	{
		ID:          "SV1070",
		Severity:    SeverityLow,
		Category:    CategoryManifest,
		Short:       "Secret is missing immutable: true",
		Description: "Immutable Secrets cannot be accidentally modified after creation, and they improve etcd performance by skipping watch notifications.",
		Remediation: "Add 'immutable: true' to your Secret manifest.",
		Example: `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
immutable: true   # ← add this
type: Opaque`,
	},
	{
		ID:          "SV1080",
		Severity:    SeverityMedium,
		Category:    CategoryManifest,
		Short:       "Cross-namespace Secret reference detected",
		Description: "References to Secrets in a different namespace can bypass namespace-scoped RBAC controls and increase the blast radius of a compromise.",
		Remediation: "Copy the Secret into the same namespace, or use External Secrets Operator with a ClusterSecretStore for cross-namespace secrets.",
	},

	// ── v0.2.0 External Secrets ───────────────────────────────────────────────
	{
		ID:          "SV2010",
		Severity:    SeverityHigh,
		Category:    CategoryExternalSecrets,
		Short:       "ExternalSecret key reference format is invalid",
		Description: "The remoteRef.key or remoteRef.property field does not match expected path conventions for the configured provider.",
		Remediation: "Check the ESO documentation for the correct key format for your provider (e.g. AWS SM: 'prod/myapp/password', Vault: 'secret/data/myapp').",
	},
	{
		ID:          "SV2020",
		Severity:    SeverityHigh,
		Category:    CategoryExternalSecrets,
		Short:       "SecretStore provider configuration is missing required fields",
		Description: "The SecretStore or ClusterSecretStore spec.provider block is missing required fields such as region, service, or server.",
		Remediation: "Add all required provider configuration fields. Refer to the ESO provider documentation.",
	},
	{
		ID:          "SV2030",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "ExternalSecret refreshInterval exceeds 24 hours",
		Description: "A long refresh interval means rotated secrets in the backend may not propagate to Kubernetes for an extended period, leaving stale (possibly revoked) values in use.",
		Remediation: "Set refreshInterval to 1h or less for secrets that rotate frequently.",
	},
	{
		ID:          "SV2040",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "ExternalSecret uses creationPolicy: Merge (unintended overwrite risk)",
		Description: "creationPolicy: Merge will merge remote keys into an existing Secret, potentially overwriting keys managed by other ExternalSecrets or manually.",
		Remediation: "Change creationPolicy to 'Owner' (default) unless intentional merging is required.",
	},
	{
		ID:          "SV2050",
		Severity:    SeverityLow,
		Category:    CategoryExternalSecrets,
		Short:       "ExternalSecret remoteRef key may contain a typo",
		Description: "The remoteRef.key path contains patterns that suggest a typo (double slashes, trailing slashes, unusual characters).",
		Remediation: "Verify the remoteRef.key path matches the exact key path in your secret backend.",
	},
	{
		ID:          "SV2060",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "VaultStaticSecret / VaultDynamicSecret path configuration issue",
		Description: "The Vault secret path is missing, empty, or does not follow expected conventions (e.g. 'secret/data/...' for KV v2).",
		Remediation: "Verify the Vault path and mount configuration. For KV v2, paths must include 'data/' in the path.",
	},
	{
		ID:          "SV2070",
		Severity:    SeverityHigh,
		Category:    CategoryExternalSecrets,
		Short:       "Vault role has overly broad permissions",
		Description: "The Vault role referenced in VaultAuth grants access to a wildcard path ('*') or an unusually broad set of capabilities.",
		Remediation: "Scope Vault policies to the minimum required paths and capabilities.",
	},
	{
		ID:          "SV2080",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "VaultDynamicSecret missing leaseRenewalPercent",
		Description: "Without leaseRenewalPercent, the Vault lease may expire before renewal, causing authentication failures.",
		Remediation: "Set spec.leaseRenewalPercent: 67 to renew the lease at 67% of its TTL.",
	},
	{
		ID:          "SV2090",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "IAM role has overly broad secret read permissions",
		Description: "The IAM role or policy grants access to all secrets ('*') or an unusually broad resource ARN pattern.",
		Remediation: "Scope IAM policies to specific secret ARNs using the principle of least privilege.",
	},
	{
		ID:          "SV2100",
		Severity:    SeverityMedium,
		Category:    CategoryExternalSecrets,
		Short:       "ExternalSecret auto-refresh is disabled (refreshInterval: 0)",
		Description: "Setting refreshInterval to 0 disables automatic secret refresh. Rotated backend secrets will never be picked up.",
		Remediation: "Set a non-zero refreshInterval (e.g. 1h) to enable automatic secret refresh.",
	},

	// ── v0.3.0 Git history ────────────────────────────────────────────────────
	{
		ID:          "SV3010",
		Severity:    SeverityMedium,
		Category:    CategoryGit,
		Short:       ".gitignore is missing a pattern for secret file types",
		Description: "Files like .env, *.pem, and *secret* are commonly used to store secrets locally. Without gitignore patterns, they can be accidentally committed.",
		Remediation: "Add the missing pattern to .gitignore (e.g. '.env', '*.pem', '*secret*').",
	},
	{
		ID:          "SV3020",
		Severity:    SeverityCritical,
		Category:    CategoryGit,
		Short:       ".env or environment file was committed to git history",
		Description: "An environment file (.env, .env.local, .env.production, etc.) was found in git history. These files typically contain plaintext secrets that remain accessible in git history even after deletion.",
		Remediation: "Remove the file from git history using 'git filter-repo' or BFG Repo Cleaner, then rotate all exposed secrets.",
	},
	{
		ID:          "SV3030",
		Severity:    SeverityCritical,
		Category:    CategoryGit,
		Short:       "Known secret pattern found in git history",
		Description: "A commit in git history contains a line matching a known secret pattern (AWS key, GitHub token, etc.). The secret may have been deleted from the working tree but remains accessible in history.",
		Remediation: "Remove the secret from git history using 'git filter-repo', then immediately rotate the exposed credentials.",
	},
	{
		ID:          "SV3040",
		Severity:    SeverityMedium,
		Category:    CategoryGit,
		Short:       "High-entropy token found in git history (possible secret)",
		Description: "A committed line contains a high-entropy string that may be a secret. This is a probabilistic detection — review the finding to confirm.",
		Remediation: "If confirmed as a secret, remove it from git history and rotate the credential.",
	},
	{
		ID:          "SV3050",
		Severity:    SeverityHigh,
		Category:    CategoryGit,
		Short:       "Secret pattern found in Helm values.yaml in git history",
		Description: "A Helm values.yaml file in git history contains a known secret pattern. Helm values are often committed to version control, making them accessible to anyone with repo access.",
		Remediation: "Remove the secret from git history, rotate the credential, and use Helm Secrets or ESO for future deployments.",
	},

	// ── v0.4.0 Live cluster ───────────────────────────────────────────────────
	{
		ID:          "SV4010",
		Severity:    SeverityCritical,
		Category:    CategoryCluster,
		Short:       "etcd secrets are not encrypted at rest",
		Description: "Kubernetes Secrets are stored in etcd without encryption. Anyone with etcd access can read all secrets in plaintext.",
		Remediation: "Configure EncryptionConfiguration with an encryption provider (aescbc, aesgcm, or kms) and run 'kubectl get secrets --all-namespaces -o json | kubectl replace -f -' to re-encrypt existing secrets.",
	},
	{
		ID:          "SV4030",
		Severity:    SeverityMedium,
		Category:    CategoryCluster,
		Short:       "Pod auto-mounts ServiceAccount token unnecessarily",
		Description: "automountServiceAccountToken is not set to false. The pod receives a ServiceAccount token that grants Kubernetes API access, even if the application doesn't need it.",
		Remediation: "Set automountServiceAccountToken: false on the Pod spec or ServiceAccount if the pod doesn't need API server access.",
	},
	{
		ID:          "SV4040",
		Severity:    SeverityMedium,
		Category:    CategoryCluster,
		Short:       "Secret volume mounted without readOnly: true",
		Description: "A Secret volume is mounted without readOnly: true. A compromised container could modify the mounted secret, potentially affecting other pods that share it.",
		Remediation: "Add readOnly: true to the volumeMount definition.",
	},
	{
		ID:          "SV4050",
		Severity:    SeverityHigh,
		Category:    CategoryCluster,
		Short:       "RBAC role grants broad secret access (list/watch)",
		Description: "A Role or ClusterRole grants list or watch verbs on secrets. This allows a principal to enumerate all secrets in the namespace/cluster, not just read specific ones.",
		Remediation: "Replace list/watch on secrets with get on specific named secrets. Use resourceNames to scope access.",
	},
	{
		ID:          "SV4060",
		Severity:    SeverityHigh,
		Category:    CategoryCluster,
		Short:       "Default ServiceAccount has secret access",
		Description: "The default ServiceAccount in a namespace has been granted access to Secrets. Since all pods use the default SA by default, this gives every pod in the namespace secret access.",
		Remediation: "Remove secret permissions from the default ServiceAccount. Create dedicated ServiceAccounts with minimal permissions for each workload.",
	},

	// ── v0.7.0 Helm / Kustomize ───────────────────────────────────────────────
	{
		ID:          "SV6010",
		Severity:    SeverityHigh,
		Category:    CategoryHelmKustomize,
		Short:       "Plaintext secret in Helm values.yaml",
		Description: "A values.yaml or values-*.yaml file contains a known secret pattern or high-entropy value at a suspicious key (password, token, apiKey, etc.). Values files are typically committed to git.",
		Remediation: "Use the Helm Secrets plugin (sops-based encryption) or External Secrets Operator. Pass secrets via --set from CI secret stores, not in values.yaml.",
	},
	{
		ID:          "SV6020",
		Severity:    SeverityHigh,
		Category:    CategoryHelmKustomize,
		Short:       "Kustomize secretGenerator references a .env file",
		Description: "A secretGenerator entry uses envs: with a .env or .env.* file. The .env file must exist in the repository, meaning plaintext secrets may be committed to git.",
		Remediation: "Replace with External Secrets Operator or Sealed Secrets. If using .env files, ensure they are gitignored and generated by CI from a secret store.",
	},
	{
		ID:          "SV6030",
		Severity:    SeverityHigh,
		Category:    CategoryHelmKustomize,
		Short:       "Kustomize secretGenerator contains plaintext literals",
		Description: "A secretGenerator entry uses literals: with key=value pairs that contain known secret patterns or high-entropy values. These literals are stored in kustomization.yaml in plaintext.",
		Remediation: "Remove plaintext secrets from literals[]. Use a gitignored .env file generated by CI, or External Secrets Operator.",
	},
	{
		ID:          "SV6040",
		Severity:    SeverityMedium,
		Category:    CategoryHelmKustomize,
		Short:       "Helm directly manages a Kubernetes Secret",
		Description: "A Secret resource has Helm management labels/annotations (app.kubernetes.io/managed-by: Helm). Helm-managed Secrets require secret values in values.yaml or --set flags, both of which risk exposure in git or CI logs.",
		Remediation: "Use External Secrets Operator (create an ExternalSecret instead of a Secret in chart templates) or the Helm Secrets plugin.",
	},
}

// RuleMetadataByID returns the metadata for a given rule ID, or nil if not found.
func RuleMetadataByID(id string) *RuleMetadata {
	for i := range AllRules {
		if AllRules[i].ID == id {
			return &AllRules[i]
		}
	}
	return nil
}
