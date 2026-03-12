# CLAUDE.md — SecretsVet

SecretsVet is a Kubernetes secret misconfiguration scanner CLI written in Go.
This file gives AI agents the information needed to use, test, and extend it.

---

## What the tool does

Detects plaintext secrets and weak secret configurations across:

1. **YAML manifests** — `env[]`, ConfigMap data, Secret resources
2. **git history** — all commits including deleted files
3. **Helm / Kustomize** — `values.yaml`, `secretGenerator`
4. **Live clusters** — etcd encryption, RBAC, SA token mounts

---

## How to build and run

```bash
# Build
go build -o secretsvet .

# Run tests
go test ./...

# Run without installing
go run . scan ./k8s/
```

---

## Commands at a glance

```
secretsvet scan [path...]       Scan YAML manifests
secretsvet git-scan [path]      Scan git commit history
secretsvet cluster-scan         Scan live cluster via kubectl
secretsvet rules                List all 32 rules
secretsvet init [path]          Generate .secretsvet.yaml
secretsvet version              Print version
```

Global flags available on all commands:
```
--output / -o   tty (default) | json | sarif | github-actions
--config        path to .secretsvet.yaml (default: .secretsvet.yaml)
--no-color      disable ANSI color
```

---

## scan — key flags

```
--exit-code              exit 1 if findings exist
--min-severity           LOW | MEDIUM | HIGH | CRITICAL (default LOW)
--recursive / -r         recurse into subdirectories (default true)
--helm <dir>             run helm template <dir> and scan output
--kustomize              run kustomize build and scan output
--fix                    print fix suggestion per finding
--fix-lang               en | ja (default en)
--fix-llm                use Claude API for fix (needs ANTHROPIC_API_KEY)
--baseline <file>        suppress findings already in baseline
--save-baseline <file>   save current findings as new baseline
```

Stdin path: `helm template ./chart | secretsvet scan -`

---

## git-scan — key flags

```
--max-commits <n>    limit to N most recent commits (0 = all)
--skip-history       only check .gitignore, skip commit scanning
--since <sha>        scan commits reachable from HEAD but not from <sha>
                     use: github.event.pull_request.base.sha in CI
```

---

## cluster-scan — key flags

```
--context <name>     kubeconfig context (default: current)
--namespace / -n     namespace (default: current)
--all-namespaces     scan all namespaces
--skip-etcd          skip etcd encryption check
--skip-rbac          skip RBAC checks
--skip-runtime       skip Pod-level runtime checks
```

Requires `kubectl` installed and cluster access configured.

---

## JSON output schema

All commands support `--output json`. Schema:

```json
{
  "version": "string",
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
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

Notes:
- `severity` values are lowercase: `critical`, `high`, `medium`, `low`
- `line` is 1-based; 0 means unknown
- `detail` always redacts secret values (e.g. `AKIA...[REDACTED]`)
- `file` is the absolute or relative path as passed to the scanner
- `git-scan --output json` wraps findings in `{"findings": [...], "commits": N, "files": N}`

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or findings exist but `--exit-code` not set) |
| 1 | Findings found when `--exit-code` is set |
| 2 | Usage error (bad flags, missing args) |

---

## Configuration file (.secretsvet.yaml)

```yaml
rules:
  SV6040:
    disabled: true          # suppress this rule entirely
  SV1070:
    severity: HIGH          # override severity

thresholds:
  entropy_min_length: 24    # default is 20

ignore:
  paths:
    - tests/**
    - "**/*_test.yaml"
```

Load via `--config <path>`. Auto-loaded from `.secretsvet.yaml` in CWD.

---

## Ignore file (.secretsvet-ignore)

```
# Rule ID — suppress globally
SV1070

# File glob — suppress all findings in matching files
testdata/**

# Commit hash prefix — suppress git-scan finding from this commit
abc12345
```

---

## Baseline workflow

Baseline suppresses known-existing findings so CI only fails on new ones:

```bash
# Save baseline (run once, commit the file)
secretsvet scan ./k8s/ --save-baseline .secretsvet-baseline.json

# CI: only fail on new findings
secretsvet scan ./k8s/ --baseline .secretsvet-baseline.json --exit-code
```

Fingerprint: SHA256[:16] of `RuleID + File + ResourceKind + ResourceName + Namespace`.
Stable across line number changes.

---

## Fix suggestions

Static templates exist for 18 rules (no API needed):
SV1010, SV1020, SV1030, SV1040, SV1050, SV1060, SV1070,
SV2030, SV2040, SV2080, SV2100, SV3010,
SV4030, SV4040,
SV6010, SV6020, SV6030, SV6040

When `--fix-llm` is set and `ANTHROPIC_API_KEY` is present, the Claude API (claude-opus-4-6) is called for rules without static templates.

---

## Rule ID scheme

```
SV1xxx  Plaintext secrets in manifests
SV2xxx  External Secrets Operator / Vault / AWS SM misconfiguration
SV3xxx  Git history leaks
SV4xxx  etcd + runtime configuration (cluster-scan)
SV6xxx  Helm / Kustomize
```

Full rule list: `secretsvet rules`
Detailed info: `secretsvet rules --id SV1010`

---

## Package structure

```
cmd/
  root.go          cobra root + global flags (--output, --config)
  scan.go          scan command
  git_scan.go      git-scan command
  cluster_scan.go  cluster-scan command
  rules.go         rules command
  init_cmd.go      init command

internal/
  k8s/             YAML loader using yaml.v3 Node API (preserves line numbers)
  rule/            Finding/Rule interfaces, per-rule files (sv1010_*.go), metadata.go
  detector/        entropy.go (Shannon), pattern.go (regex catalog)
  scanner/         scan orchestrator (applies config, baseline, helm templates)
  gitscan/         git history scan orchestrator
  git/             git log parsing, .gitignore check, .secretsvet-ignore
  cluster/         kubectl wrapper
  clusterscan/     live cluster checks
  fixer/           static fix templates + Claude API fallback
  output/          formatters: tty, json, sarif, github_actions
  config/          .secretsvet.yaml loader
  baseline/        fingerprint, save, load, filter
  version/         version string
```

Key design decisions:
- Uses `yaml.v3` Node API (not `k8s.io/api`) — preserves line numbers, keeps binary small
- Rule interface: `ID() string`, `Check(res *k8s.Resource) []rule.Finding`
- Shannon entropy thresholds: base64=4.5, hex=3.0, general=4.0, minLen=20

---

## Writing tests

Tests use Go's standard `testing` package and `t.TempDir()`.
No mocks for the filesystem — tests write actual files.
No live cluster in unit tests — cluster-scan tests are manual.

```bash
go test ./...                          # all packages
go test ./internal/scanner/... -v      # specific package
go test ./... -run TestScan_SV1010     # specific test
```

---

## Common agentic tasks

**Check what rules cover a specific resource type:**
```bash
secretsvet rules --category manifest
```

**Scan a directory and get structured output for further processing:**
```bash
secretsvet scan ./k8s/ --output json --exit-code
```

**Find only critical and high findings:**
```bash
secretsvet scan ./k8s/ --output json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
```

**Check if a repo has ever committed .env files:**
```bash
secretsvet git-scan . --skip-history --output json | jq '.findings[] | select(.rule_id == "SV3010")'
```

**Generate a config and immediately review it:**
```bash
secretsvet init && cat .secretsvet.yaml
```

**Scan only what changed in a PR (GitHub Actions context):**
```bash
secretsvet git-scan . --since "$GITHUB_BASE_SHA" --output github-actions --exit-code
```
