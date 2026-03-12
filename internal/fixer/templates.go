// Package fixer generates fix suggestions for SecretsVet findings.
package fixer

import (
	"fmt"
	"strings"

	"github.com/SecretsVet/secretsvet/internal/rule"
)

// FixSuggestion holds a fix suggestion for a finding.
type FixSuggestion struct {
	RuleID      string
	Severity    string
	Problem     string
	Solution    string
	YAMLSnippet string // fix YAML template (if applicable)
	Source      string // "static" or "llm"
}

// StaticFix generates a fix suggestion from built-in templates.
// Returns nil if no static template exists for the rule.
func StaticFix(finding rule.Finding, lang string) *FixSuggestion {
	switch finding.RuleID {
	case "SV1010", "SV1020":
		return fixEnvValue(finding, lang)
	case "SV1030":
		return fixArgsSecret(finding, lang)
	case "SV1040":
		return fixConfigMapSecret(finding, lang)
	case "SV1050":
		return fixEnvFromConfigMap(finding, lang)
	case "SV1060":
		return fixSecretInManifest(finding, lang)
	case "SV1070":
		return fixSecretNotImmutable(finding, lang)
	case "SV2030":
		return fixRefreshInterval(finding, lang)
	case "SV2040":
		return fixCreationPolicy(finding, lang)
	case "SV2080":
		return fixLeaseRenewal(finding, lang)
	case "SV2100":
		return fixRotationDisabled(finding, lang)
	case "SV3010":
		return fixGitignore(finding, lang)
	case "SV4030":
		return fixSAToken(finding, lang)
	case "SV4040":
		return fixReadonlyMount(finding, lang)
	case "SV6010":
		return fixHelmValues(finding, lang)
	case "SV6020":
		return fixKustomizeSecretGenEnv(finding, lang)
	case "SV6030":
		return fixKustomizeSecretGenLiteral(finding, lang)
	case "SV6040":
		return fixHelmManagedSecret(finding, lang)
	}
	return nil
}

func isJA(lang string) bool { return strings.ToLower(lang) == "ja" }

func fixEnvValue(f rule.Finding, lang string) *FixSuggestion {
	problem := "A secret value is hardcoded in env[].value"
	solution := "Move the secret to a Kubernetes Secret resource and reference it via valueFrom.secretKeyRef"
	if isJA(lang) {
		problem = "シークレット値が env[].value に直書きされています"
		solution = "シークレットを Kubernetes Secret リソースに移動し、valueFrom.secretKeyRef で参照してください"
	}

	// Extract env var name from Detail if possible
	envName := "MY_SECRET"
	if strings.Contains(f.Detail, "env var: ") {
		parts := strings.Split(f.Detail, "env var: ")
		if len(parts) > 1 {
			envName = strings.Split(parts[1], ",")[0]
		}
	}
	secretName := strings.ToLower(strings.ReplaceAll(envName, "_", "-"))

	yaml := fmt.Sprintf(`# Step 1: Create a Secret
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
  immutable: true
type: Opaque
stringData:
  %s: "<actual-value-here>"

---
# Step 2: Reference it in your Deployment
# Remove the old: value: "..."
# Replace with:
env:
  - name: %s
    valueFrom:
      secretKeyRef:
        name: %s
        key: %s`,
		secretName, f.Namespace, strings.ToLower(envName),
		envName, secretName, strings.ToLower(envName))

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixArgsSecret(f rule.Finding, lang string) *FixSuggestion {
	problem := "A secret is embedded in container args[] or command[]"
	solution := "Pass the secret as an environment variable sourced from a Kubernetes Secret"
	if isJA(lang) {
		problem = "シークレットが args[] または command[] に埋め込まれています"
		solution = "シークレットを Kubernetes Secret からの環境変数として渡してください"
	}

	yaml := `# Before (insecure):
args:
  - "--api-key=sk_live_XXXX"

# After (secure):
args:
  - "--api-key=$(API_KEY)"
env:
  - name: API_KEY
    valueFrom:
      secretKeyRef:
        name: my-app-secrets
        key: api-key`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixConfigMapSecret(f rule.Finding, lang string) *FixSuggestion {
	problem := "A secret is stored in a ConfigMap which is not encrypted at rest"
	solution := "Move the secret value to a Kubernetes Secret resource (encrypted at rest when etcd encryption is configured)"
	if isJA(lang) {
		problem = "シークレットが ConfigMap に保存されています。ConfigMap は保存時に暗号化されません"
		solution = "シークレット値を Kubernetes Secret リソースに移動してください（etcd 暗号化設定時に保存時暗号化されます）"
	}

	resource := f.ResourceName
	if resource == "" {
		resource = "my-config"
	}

	yaml := fmt.Sprintf(`# Before (insecure ConfigMap):
apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
data:
  DB_PASSWORD: "supersecret"  # ← remove this

---
# After: create a Secret for sensitive values
apiVersion: v1
kind: Secret
metadata:
  name: %s-secrets
  immutable: true
type: Opaque
stringData:
  DB_PASSWORD: "supersecret"

---
# Reference the Secret in your Deployment:
envFrom:
  - secretRef:
      name: %s-secrets`, resource, resource, resource)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixEnvFromConfigMap(f rule.Finding, lang string) *FixSuggestion {
	problem := "envFrom references a ConfigMap which is not encrypted at rest"
	solution := "If the ConfigMap contains sensitive data, migrate it to a Secret and use secretRef instead"
	if isJA(lang) {
		problem = "envFrom が ConfigMap を参照しています。ConfigMap は保存時に暗号化されません"
		solution = "ConfigMap にセンシティブなデータが含まれている場合は Secret に移行し secretRef を使用してください"
	}

	yaml := `# Before:
envFrom:
  - configMapRef:
      name: app-config

# After (if app-config contains secrets):
envFrom:
  - secretRef:
      name: app-secrets   # ← use secretRef
  - configMapRef:
      name: app-config    # ← keep non-sensitive values here`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixSecretInManifest(f rule.Finding, lang string) *FixSuggestion {
	problem := "Secret data is stored in the manifest file (base64-encoded but not encrypted)"
	solution := "Use External Secrets Operator or Sealed Secrets to avoid storing secrets in manifests"
	if isJA(lang) {
		problem = "シークレットデータがマニフェストファイルに保存されています（base64エンコードされていますが暗号化されていません）"
		solution = "External Secrets Operator または Sealed Secrets を使用してマニフェストにシークレットを保存しないようにしてください"
	}

	resource := f.ResourceName
	if resource == "" {
		resource = "my-secret"
	}

	yaml := fmt.Sprintf(`# Option 1: External Secrets Operator (recommended)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager  # your SecretStore
    kind: SecretStore
  target:
    name: %s
    immutable: true
  data:
    - secretKey: password
      remoteRef:
        key: prod/%s/password

---
# Option 2: Sealed Secrets (encrypt with kubeseal)
# kubeseal --format yaml < secret.yaml > sealed-secret.yaml`, resource, resource, resource)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixSecretNotImmutable(f rule.Finding, lang string) *FixSuggestion {
	problem := "Secret does not have immutable: true"
	solution := "Add 'immutable: true' to prevent accidental modification and improve etcd watch performance"
	if isJA(lang) {
		problem = "Secret に immutable: true が設定されていません"
		solution = "'immutable: true' を追加することで、誤った変更を防ぎ etcd の watch パフォーマンスを向上させます"
	}

	yaml := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
immutable: true   # ← add this
type: Opaque
data:
  # ... your data`, f.ResourceName, f.Namespace)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixRefreshInterval(f rule.Finding, lang string) *FixSuggestion {
	problem := "ExternalSecret refreshInterval exceeds 24h, delaying secret rotation"
	solution := "Reduce refreshInterval to 1h or less to ensure secrets rotate promptly"
	if isJA(lang) {
		problem = "ExternalSecret の refreshInterval が 24h を超えており、シークレットのローテーションが遅れます"
		solution = "refreshInterval を 1h 以下に短縮してシークレットが迅速にローテーションされるようにしてください"
	}

	yaml := fmt.Sprintf(`apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s
spec:
  refreshInterval: 1h   # ← was: too long, reduce to ≤24h
  # ...`, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixCreationPolicy(f rule.Finding, lang string) *FixSuggestion {
	problem := "ExternalSecret uses creationPolicy: Merge, risking unintentional Secret key overwrites"
	solution := "Change creationPolicy to 'Owner' (the default) unless intentional merging is required"
	if isJA(lang) {
		problem = "ExternalSecret が creationPolicy: Merge を使用しており、意図しない Secret キーの上書きリスクがあります"
		solution = "intentional なマージが必要でない限り、creationPolicy を 'Owner'（デフォルト）に変更してください"
	}

	yaml := fmt.Sprintf(`apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s
spec:
  target:
    name: my-secret
    creationPolicy: Owner   # ← was: Merge
  # ...`, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixLeaseRenewal(f rule.Finding, lang string) *FixSuggestion {
	problem := "VaultDynamicSecret missing leaseRenewalPercent — lease may expire"
	solution := "Set spec.leaseRenewalPercent to 67 to renew the lease at 67% of its TTL"
	if isJA(lang) {
		problem = "VaultDynamicSecret に leaseRenewalPercent が設定されていません — リースが期限切れになる可能性があります"
		solution = "リース TTL の 67% でリースを更新するように spec.leaseRenewalPercent を 67 に設定してください"
	}

	yaml := fmt.Sprintf(`apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultDynamicSecret
metadata:
  name: %s
spec:
  leaseRenewalPercent: 67   # ← add this (renew at 67%% of TTL)
  # ...`, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixRotationDisabled(f rule.Finding, lang string) *FixSuggestion {
	problem := "ExternalSecret auto-refresh is disabled (refreshInterval: 0)"
	solution := "Set a non-zero refreshInterval to enable automatic secret refresh"
	if isJA(lang) {
		problem = "ExternalSecret の自動更新が無効になっています（refreshInterval: 0）"
		solution = "ゼロ以外の refreshInterval を設定してシークレットの自動更新を有効にしてください"
	}

	yaml := fmt.Sprintf(`apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s
spec:
  refreshInterval: 1h   # ← was: 0 (disabled), set to non-zero
  # ...`, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixGitignore(f rule.Finding, lang string) *FixSuggestion {
	// Extract missing pattern from message
	pattern := "*.env"
	if strings.Contains(f.Message, "missing a pattern for ") {
		parts := strings.Split(f.Message, "missing a pattern for ")
		if len(parts) > 1 {
			pattern = strings.Split(parts[1], " ")[0]
		}
	}

	problem := fmt.Sprintf(".gitignore is missing '%s' — files matching this pattern may be committed", pattern)
	solution := fmt.Sprintf("Add '%s' to .gitignore to prevent accidental commits", pattern)
	if isJA(lang) {
		problem = fmt.Sprintf(".gitignore に '%s' が含まれていません — このパターンに一致するファイルがコミットされる可能性があります", pattern)
		solution = fmt.Sprintf("誤ったコミットを防ぐために .gitignore に '%s' を追加してください", pattern)
	}

	snippet := fmt.Sprintf(`# Add to .gitignore:
%s`, pattern)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: snippet,
		Source:      "static",
	}
}

func fixSAToken(f rule.Finding, lang string) *FixSuggestion {
	problem := "Pod auto-mounts service account token — this gives unnecessary API access"
	solution := "Set automountServiceAccountToken: false if the pod doesn't need Kubernetes API access"
	if isJA(lang) {
		problem = "Pod がサービスアカウントトークンを自動マウントしています — 不要な API アクセスを付与します"
		solution = "Pod が Kubernetes API アクセスを必要としない場合は automountServiceAccountToken: false を設定してください"
	}

	yaml := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  template:
    spec:
      automountServiceAccountToken: false   # ← add this
      containers:
        # ...`, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixHelmValues(f rule.Finding, lang string) *FixSuggestion {
	problem := "Helm values.yaml contains a plaintext secret — this file is typically committed to git"
	solution := "Remove the secret from values.yaml and use the Helm Secrets plugin or External Secrets Operator instead"
	if isJA(lang) {
		problem = "Helm values.yaml に平文シークレットが含まれています — このファイルは通常 git にコミットされます"
		solution = "values.yaml からシークレットを削除し、Helm Secrets プラグインまたは External Secrets Operator を使用してください"
	}

	yaml := `# Option 1: Helm Secrets plugin (sops-based encryption)
# Install: helm plugin install https://github.com/jkroepke/helm-secrets
# Encrypt:  helm secrets encrypt values-secrets.yaml > values-secrets.enc.yaml
# Deploy:   helm secrets upgrade myapp ./chart -f values.yaml -f values-secrets.enc.yaml

# Option 2: Reference from environment (--set via CI secret store)
# In values.yaml — replace plaintext with an empty default:
myApp:
  apiKey: ""   # ← injected at deploy time via: helm upgrade --set myApp.apiKey=$SECRET

# Option 3: External Secrets Operator (recommended for production)
# Remove the key from values.yaml entirely and use an ExternalSecret resource`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixKustomizeSecretGenEnv(f rule.Finding, lang string) *FixSuggestion {
	problem := "secretGenerator references a .env file — the file must exist in the repo, exposing plaintext secrets"
	solution := "Replace the .env file reference with External Secrets Operator or a CI-injected Secret"
	if isJA(lang) {
		problem = "secretGenerator が .env ファイルを参照しています — このファイルはリポジトリに存在する必要があり、平文シークレットが露出します"
		solution = ".env ファイル参照を External Secrets Operator または CI 注入型 Secret に置き換えてください"
	}

	yaml := `# Before (insecure — .env file committed to git):
secretGenerator:
  - name: my-app-secrets
    envs:
      - .env   # ← remove this

---
# After Option 1: ExternalSecret (recommended)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: my-app-secrets
  dataFrom:
    - extract:
        key: prod/my-app

---
# After Option 2: Sealed Secrets
# kubeseal < secret.yaml > sealed-secret.yaml
# Commit sealed-secret.yaml (encrypted) instead of .env`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixKustomizeSecretGenLiteral(f rule.Finding, lang string) *FixSuggestion {
	problem := "secretGenerator literal[] contains a plaintext secret directly in kustomization.yaml"
	solution := "Remove the literal value and source the secret from a secure backend (ESO, Sealed Secrets)"
	if isJA(lang) {
		problem = "secretGenerator literal[] に平文シークレットが kustomization.yaml に直書きされています"
		solution = "literal 値を削除し、安全なバックエンド（ESO、Sealed Secrets）からシークレットを取得してください"
	}

	yaml := `# Before (insecure):
secretGenerator:
  - name: my-secret
    literals:
      - password=supersecret   # ← never hardcode here

---
# After: use envs[] pointing to a file that is gitignored
# (generate the file in CI from a secret store)
secretGenerator:
  - name: my-secret
    envs:
      - .env.generated   # ← generated by CI, in .gitignore

# Or use External Secrets Operator — no kustomize secretGenerator needed`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixHelmManagedSecret(f rule.Finding, lang string) *FixSuggestion {
	problem := "Helm directly manages this Secret — secret values must be in values.yaml or passed via --set, risking exposure in git or CI logs"
	solution := "Use External Secrets Operator or Helm Secrets plugin to manage secrets outside of Helm values"
	if isJA(lang) {
		problem = "Helm がこの Secret を直接管理しています — シークレット値は values.yaml または --set で渡す必要があり、git や CI ログへの漏洩リスクがあります"
		solution = "External Secrets Operator または Helm Secrets プラグインを使用して Helm values 外でシークレットを管理してください"
	}

	yaml := fmt.Sprintf(`# Recommended: replace Helm-managed Secret with ExternalSecret
# Remove the Secret from your Helm chart templates/ directory.
# Add an ExternalSecret instead:
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: %s
  namespace: %s
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: my-secret-store
    kind: SecretStore
  target:
    name: %s
  dataFrom:
    - extract:
        key: prod/%s`, f.ResourceName, f.Namespace, f.ResourceName, f.ResourceName)

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}

func fixReadonlyMount(f rule.Finding, lang string) *FixSuggestion {
	problem := "Secret volume is mounted without readOnly: true — container can modify the secret"
	solution := "Add readOnly: true to the volumeMount to prevent container from writing to the secret"
	if isJA(lang) {
		problem = "Secret ボリュームが readOnly: true なしでマウントされています — コンテナがシークレットを変更できます"
		solution = "コンテナがシークレットに書き込めないよう volumeMount に readOnly: true を追加してください"
	}

	yaml := `volumeMounts:
  - name: my-secret-vol
    mountPath: /etc/secrets
    readOnly: true   # ← add this`

	return &FixSuggestion{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Problem:     problem,
		Solution:    solution,
		YAMLSnippet: yaml,
		Source:      "static",
	}
}
