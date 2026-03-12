# SecretsVet

**Kubernetes secret misconfiguration scanner** — detects plaintext secrets, weak configurations, and historical leaks across manifests, git history, Helm/Kustomize, and live clusters.

```
secretsvet scan ./k8s/
secretsvet git-scan .
secretsvet cluster-scan --all-namespaces
```

---

## Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [scan](#scan)
  - [git-scan](#git-scan)
  - [cluster-scan](#cluster-scan)
  - [rules](#rules)
  - [init](#init)
- [Output Formats](#output-formats)
- [Configuration (.secretsvet.yaml)](#configuration-secretsvetyaml)
- [Baseline Suppression](#baseline-suppression)
- [Fix Suggestions](#fix-suggestions)
- [CI/CD Integration](#cicd-integration)
- [Rule Reference](#rule-reference)
- [K8sVet Integration](#k8svet-integration)

---

## Installation

**From source (requires Go 1.21+):**

```bash
git clone https://github.com/SecretsVet/secretsvet
cd secretsvet
go install .
```

**Requirements:**

| Feature | Dependency |
|---------|------------|
| `cluster-scan` | `kubectl` configured |
| `scan --kustomize` | `kustomize` CLI |
| `scan --helm <dir>` | `helm` CLI |
| `--fix-llm` | `ANTHROPIC_API_KEY` env var |

---

## Quick Start

```bash
# Scan YAML manifests
secretsvet scan ./k8s/

# Scan entire git history
secretsvet git-scan .

# Scan live cluster
secretsvet cluster-scan

# Generate a config file tailored to your repo
secretsvet init

# List all 32 detection rules
secretsvet rules
```

---

## Commands

### `scan`

Scans YAML manifests for secret misconfigurations. Accepts files, directories, or `-` for stdin.

```bash
# Directory (recursive by default)
secretsvet scan ./k8s/

# Single file
secretsvet scan deploy.yaml

# Multiple paths
secretsvet scan ./base/ ./overlays/prod/

# Stdin (pipe from helm/kustomize)
helm template ./mychart | secretsvet scan -
kustomize build ./overlays/prod | secretsvet scan -

# Run helm template automatically
secretsvet scan ./k8s/ --helm ./charts/myapp

# Run kustomize build automatically
secretsvet scan ./k8s/ --kustomize

# Filter by severity
secretsvet scan ./k8s/ --min-severity HIGH

# Exit code 1 on any finding (for CI)
secretsvet scan ./k8s/ --exit-code
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--recursive` / `-r` | `true` | Recurse into subdirectories |
| `--min-severity` | `LOW` | Minimum severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--exit-code` | `false` | Exit 1 if any findings are reported |
| `--fix` | `false` | Print fix suggestions for each finding |
| `--fix-lang` | `en` | Fix language: `en`, `ja` |
| `--fix-llm` | `false` | Use Claude API for fix suggestions |
| `--helm <dir>` | — | Run `helm template <dir>` and scan output |
| `--kustomize` | `false` | Run `kustomize build` and scan output |
| `--baseline <file>` | — | Suppress findings present in baseline file |
| `--save-baseline <file>` | — | Save current findings as a baseline |

---

### `git-scan`

Scans a git repository's **full commit history** for secrets — including deleted files and all branches.

```bash
# Scan current repo
secretsvet git-scan .

# Scan specific repo
secretsvet git-scan /path/to/repo

# Limit to 100 most recent commits
secretsvet git-scan . --max-commits 100

# Only check .gitignore (skip history)
secretsvet git-scan . --skip-history

# Scan only commits since a base SHA (for PR scans in CI)
secretsvet git-scan . --since $BASE_SHA

# JSON output
secretsvet git-scan . --output json
```

**Detects:**

- SV3010 — `.gitignore` missing patterns for secret file types
- SV3020 — `.env` / `.env.*` files ever committed (CRITICAL)
- SV3030 — Known secret patterns in commit history (AWS, GCP, GitHub, Slack, Stripe, Twilio...)
- SV3040 — High-entropy tokens in commit history
- SV3050 — Secrets in Helm `values.yaml` in history

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-commits` | `0` (all) | Maximum commits to scan |
| `--skip-history` | `false` | Only check `.gitignore`, skip history scan |
| `--since <sha>` | — | Scan only commits between this SHA and HEAD |

---

### `cluster-scan`

Scans a **running Kubernetes cluster** via `kubectl`. Requires configured cluster access.

```bash
# Current context, current namespace
secretsvet cluster-scan

# Specific context, all namespaces
secretsvet cluster-scan --context production --all-namespaces

# Specific namespace
secretsvet cluster-scan --namespace myapp

# Skip expensive checks
secretsvet cluster-scan --skip-etcd --skip-rbac

# JSON output
secretsvet cluster-scan --output json
```

**Detects:**

- SV4010 — etcd secrets not encrypted at rest (CRITICAL)
- SV4030 — Pod auto-mounts ServiceAccount token unnecessarily
- SV4040 — Secret volume mounted without `readOnly: true`
- SV4050 — RBAC role grants `list`/`watch` on Secrets (HIGH)
- SV4060 — `default` ServiceAccount has Secret access

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--context` | current | Kubeconfig context name |
| `--namespace` / `-n` | current | Namespace to scan |
| `--all-namespaces` | `false` | Scan all namespaces |
| `--skip-etcd` | `false` | Skip etcd encryption checks |
| `--skip-rbac` | `false` | Skip RBAC checks |
| `--skip-runtime` | `false` | Skip runtime configuration checks |

---

### `rules`

Lists all 32 detection rules. Useful for understanding what SecretsVet checks and for configuring suppressions.

```bash
# List all rules
secretsvet rules

# Show detailed info for one rule
secretsvet rules --id SV1010

# Filter by category
secretsvet rules --category git
secretsvet rules --category manifest
secretsvet rules --category external-secrets
secretsvet rules --category cluster
secretsvet rules --category helm-kustomize
```

---

### `init`

Generates a `.secretsvet.yaml` config file tailored to the repository structure.

```bash
# Generate in current directory
secretsvet init

# Generate for a specific path
secretsvet init /path/to/repo

# Overwrite existing file
secretsvet init --force
```

Automatically detects:
- Helm charts → suggests `scan --helm` ignore patterns
- Kustomize overlays → adds `secretGenerator` guidance
- Test directories → offers to exclude from scanning
- `.env` files → suggests `.gitignore` patterns

---

## Output Formats

All commands accept `--output` (or `-o`):

| Format | Flag | Best for |
|--------|------|----------|
| TTY (color) | `tty` (default) | Terminal |
| JSON | `json` | CI pipelines, `jq` processing |
| SARIF | `sarif` | GitHub Code Scanning |
| GitHub Actions | `github-actions` | PR annotations |

### JSON

```bash
secretsvet scan ./k8s/ --output json
```

```json
{
  "version": "0.1.0-dev",
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "rule_id": "SV1010",
      "severity": "high",
      "message": "env[].value contains a secret pattern (aws-access-key-id)",
      "file": "deploy.yaml",
      "line": 14,
      "resource_kind": "Deployment",
      "resource_name": "my-app",
      "namespace": "default",
      "detail": "env var: AWS_SECRET_KEY, value: AKIA...[REDACTED]"
    }
  ]
}
```

```bash
# Filter HIGH+ findings with jq
secretsvet scan ./k8s/ --output json | jq '.findings[] | select(.severity == "high" or .severity == "critical")'
```

### SARIF

Integrates with GitHub Advanced Security / Code Scanning:

```yaml
- run: secretsvet scan ./k8s/ --output sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitHub Actions annotations

Outputs `::error` and `::warning` workflow commands for inline PR annotations:

```yaml
- run: secretsvet scan ./k8s/ --output github-actions --exit-code
```

---

## Configuration (`.secretsvet.yaml`)

Generate a starter config with `secretsvet init`, or create manually:

```yaml
# .secretsvet.yaml

rules:
  # Disable a rule entirely
  SV6040:
    disabled: true

  # Override severity for a rule
  SV1070:
    severity: HIGH

thresholds:
  # Minimum token length for entropy checks (default: 20)
  entropy_min_length: 24

ignore:
  paths:
    - tests/**
    - "**/*_test.yaml"
    - testdata/**
```

Load a config from a custom path:

```bash
secretsvet scan ./k8s/ --config /path/to/.secretsvet.yaml
```

### `.secretsvet-ignore`

For suppressing specific findings by rule ID, file glob, or commit hash:

```
# Ignore a rule globally
SV1070

# Ignore a file pattern
testdata/**
internal/**/*_test.go

# Ignore a specific commit (git-scan)
abc12345
```

---

## Baseline Suppression

Baseline suppression lets teams introduce SecretsVet without fixing all existing findings at once — only **new** findings fail CI.

```bash
# Step 1: Save current state as baseline
secretsvet scan ./k8s/ --save-baseline .secretsvet-baseline.json

# Step 2: In CI, only report findings not in baseline
secretsvet scan ./k8s/ --baseline .secretsvet-baseline.json --exit-code
```

Fingerprints are based on `RuleID + File + ResourceKind + ResourceName + Namespace` — stable across line number changes.

Commit the baseline file to version control.

---

## Fix Suggestions

```bash
# Static fix templates (built-in, no API key needed)
secretsvet scan ./k8s/ --fix

# Japanese explanations
secretsvet scan ./k8s/ --fix --fix-lang ja

# Claude API for rules without static templates
ANTHROPIC_API_KEY=sk-... secretsvet scan ./k8s/ --fix --fix-llm
```

Each finding includes:
- **Problem** — why the finding is a security risk
- **Solution** — recommended remediation
- **YAML snippet** — ready-to-apply fix

Static templates exist for: SV1010, SV1020, SV1030, SV1040, SV1050, SV1060, SV1070, SV2030, SV2040, SV2080, SV2100, SV3010, SV4030, SV4040, SV6010, SV6020, SV6030, SV6040.

---

## CI/CD Integration

### GitHub Actions — full workflow

```yaml
# .github/workflows/secretsvet.yml
name: SecretsVet

on:
  push:
    branches: [main]
  pull_request:

jobs:
  secretsvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for git-scan

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install SecretsVet
        run: go install github.com/SecretsVet/secretsvet@latest

      # Scan manifests with SARIF upload
      - name: Scan manifests
        run: secretsvet scan ./k8s/ --output sarif > manifest.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: manifest.sarif
        if: always()

      # PR-scoped git-scan (only new commits)
      - name: Scan git history (PR)
        if: github.event_name == 'pull_request'
        run: |
          secretsvet git-scan . \
            --since ${{ github.event.pull_request.base.sha }} \
            --output github-actions \
            --exit-code

      # Full git-scan on main
      - name: Scan git history (full)
        if: github.event_name == 'push'
        run: secretsvet git-scan . --output github-actions --exit-code
```

### GitHub Actions — baseline mode (recommended for brownfield projects)

```yaml
# On main: save baseline
- name: Update baseline
  if: github.ref == 'refs/heads/main'
  run: |
    secretsvet scan ./k8s/ --save-baseline .secretsvet-baseline.json
    git add .secretsvet-baseline.json
    git diff --staged --quiet || git commit -m "chore: update secretsvet baseline"

# On PR: only new findings fail
- name: Check for new findings
  if: github.event_name == 'pull_request'
  run: |
    secretsvet scan ./k8s/ \
      --baseline .secretsvet-baseline.json \
      --output github-actions \
      --exit-code
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretsvet
        name: SecretsVet
        entry: secretsvet scan
        args: [--exit-code, --min-severity, HIGH]
        language: system
        types: [yaml]
```

---

## Rule Reference

### SV1xxx — Plaintext secrets (manifests)

| ID | Severity | Description |
|----|----------|-------------|
| SV1010 | HIGH | Secret pattern in `env[].value` (AWS, GitHub, Stripe, etc.) |
| SV1020 | MEDIUM | High-entropy string in `env[].value` |
| SV1030 | HIGH | Secret embedded in `args[]` or `command[]` |
| SV1040 | HIGH | Plaintext secret in ConfigMap `data` |
| SV1050 | LOW | `envFrom` references a ConfigMap instead of a Secret |
| SV1060 | HIGH | Secret resource data contains known pattern (after base64 decode) |
| SV1070 | LOW | Secret missing `immutable: true` |
| SV1080 | MEDIUM | Cross-namespace Secret reference |

### SV2xxx — External Secrets misconfiguration

| ID | Severity | Description |
|----|----------|-------------|
| SV2010 | HIGH | ExternalSecret key reference format is invalid |
| SV2020 | HIGH | SecretStore provider config is missing required fields |
| SV2030 | MEDIUM | `refreshInterval` exceeds 24 hours |
| SV2040 | MEDIUM | `creationPolicy: Merge` — unintended overwrite risk |
| SV2050 | LOW | `remoteRef.key` may contain a typo |
| SV2060 | MEDIUM | VaultStaticSecret / VaultDynamicSecret path config issue |
| SV2070 | HIGH | Vault role has overly broad permissions |
| SV2080 | MEDIUM | VaultDynamicSecret missing `leaseRenewalPercent` |
| SV2090 | MEDIUM | IAM role has overly broad secret read permissions |
| SV2100 | MEDIUM | Secret auto-refresh disabled (`refreshInterval: 0`) |

### SV3xxx — Git history leaks

| ID | Severity | Description |
|----|----------|-------------|
| SV3010 | MEDIUM | `.gitignore` missing patterns for secret file types |
| SV3020 | CRITICAL | `.env` or environment file committed to git history |
| SV3030 | CRITICAL | Known secret pattern found in git history |
| SV3040 | MEDIUM | High-entropy token found in git history |
| SV3050 | HIGH | Secret in Helm `values.yaml` in git history |

### SV4xxx — etcd / runtime configuration

| ID | Severity | Description |
|----|----------|-------------|
| SV4010 | CRITICAL | etcd secrets not encrypted at rest |
| SV4030 | MEDIUM | Pod auto-mounts ServiceAccount token unnecessarily |
| SV4040 | MEDIUM | Secret volume mounted without `readOnly: true` |
| SV4050 | HIGH | RBAC role grants `list`/`watch` on Secrets |
| SV4060 | HIGH | `default` ServiceAccount has Secret access |

### SV6xxx — Helm / Kustomize

| ID | Severity | Description |
|----|----------|-------------|
| SV6010 | HIGH | Plaintext secret in Helm `values.yaml` |
| SV6020 | HIGH | Kustomize `secretGenerator` references a `.env` file |
| SV6030 | HIGH | Kustomize `secretGenerator.literals[]` contains plaintext secret |
| SV6040 | MEDIUM | Helm directly manages a Kubernetes Secret |

---

## K8sVet Integration

SecretsVet is designed to run as a sub-scanner inside [K8sVet](https://github.com/k8svet/k8svet):

```bash
k8svet scan .
# → [SecretsVet]  ./  28 errors (secrets in env: 12, git history: 8, ESO config: 8)

k8svet scan --cluster --all-namespaces
# → [SecretsVet]  cluster://  5 errors (etcd unencrypted, SA token over-exposed x4)
```

K8sVet auto-invokes SecretsVet when it detects:
- `ExternalSecret` / `SecretStore` resources → runs ESO validation
- `--cluster` flag → runs etcd encryption + SA token checks

> **Planned (not yet available):** Detection of `.env` / `.env.*` files to auto-invoke `git-scan` mode is on the K8sVet roadmap but is not part of the current released integration. Use `secretsvet git-scan .` directly in the meantime.

---

## License

MIT
