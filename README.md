# SecretsVet

Kubernetes 環境における機密情報の漏洩・設定ミスを多層的に検出するセキュリティスキャナー。

manifest の `env` 直書きに留まらず、ConfigMap・git 履歴・External Secrets・etcd 暗号化まで網羅する。

---

## K8sVet との統合 (主要ユースケース)

SecretsVet は **[K8sVet](https://github.com/k8svet/k8svet) から呼び出されることを主目的として設計されています**。
K8sVet の統合ランナーとして動作し、`k8svet scan` コマンドにシークレット検証機能を追加します。

```bash
# K8sVet 経由での使用イメージ
k8svet scan .
# → [SecretsVet]  ./  28 errors (secrets in env: 12, git history: 8, ESO config: 8)

k8svet scan --cluster --all-namespaces
# → [SecretsVet]  cluster://  5 errors (etcd unencrypted, SA token over-exposed x4)
```

### K8sVet 統合ロードマップ

| SecretsVet | K8sVet | 内容 |
|---|---|---|
| v0.1.0 | K8sVet v0.5.0 | `k8svet scan .` に `secretsvet` ランナー追加 |
| v0.4.0 | K8sVet v0.5.0 | `k8svet scan --cluster` にシークレット検証追加 |
| v0.5.0 | K8sVet v0.6.0 | `k8svet scan . --fix` に SecretsVet 修正提案を統合 |

### K8sVet 自動検出ルール

K8sVet は以下のシグナルを検出した場合、自動的に SecretsVet を呼び出します:

- `.env` / `.env.*` ファイルが存在する → git スキャンモードで実行
- `ExternalSecret` / `SecretStore` を含む YAML → ESO 検証を実行
- `--cluster` モード → etcd 暗号化・SA トークン設定を検証

---

## スタンドアロン使用

K8sVet なしで単体 CLI として使用することもできます。

### インストール

```bash
go install github.com/SecretsVet/secretsvet@latest
```

またはソースからビルド:

```bash
git clone https://github.com/SecretsVet/secretsvet
cd secretsvet
make install
```

### 必要環境

- Go 1.21 以上
- `kubectl` (cluster-scan を使用する場合)
- `kustomize` (--kustomize フラグを使用する場合)
- `ANTHROPIC_API_KEY` 環境変数 (`--fix-llm` フラグを使用する場合)

---

## スキャンモード

### 1. マニフェストスキャン (`scan`)

YAML マニフェストから静的にシークレット設定ミスを検出します。

```bash
# ディレクトリを再帰スキャン
secretsvet scan ./k8s/

# 単一ファイル
secretsvet scan deploy.yaml

# JSON 出力 (CI/CD 連携向け)
secretsvet scan ./manifests/ --output json

# SARIF 出力 (GitHub Code Scanning 向け)
secretsvet scan ./k8s/ --output sarif

# Kustomize ビルド後のマニフェストをスキャン
secretsvet scan ./overlays/prod/ --kustomize

# 重大度でフィルタ
secretsvet scan ./k8s/ --min-severity HIGH

# CI/CD: 問題があれば exit code 1
secretsvet scan ./k8s/ --exit-code
```

### 2. git 履歴スキャン (`git-scan`)

git リポジトリの全コミット履歴を検索し、過去に漏洩した機密情報を検出します。

```bash
# カレントディレクトリのリポジトリをスキャン
secretsvet git-scan .

# 特定のリポジトリ
secretsvet git-scan /path/to/repo

# 最新 100 コミットのみ
secretsvet git-scan . --max-commits 100

# .gitignore 設定のみチェック (履歴スキャンをスキップ)
secretsvet git-scan . --skip-history

# JSON 出力
secretsvet git-scan . --output json
```

### 3. ライブクラスタースキャン (`cluster-scan`)

稼働中の Kubernetes クラスターのシークレット設定を検証します。`kubectl` が設定済みである必要があります。

```bash
# デフォルトコンテキストでスキャン
secretsvet cluster-scan

# 特定のコンテキストと全 namespace
secretsvet cluster-scan --context production --all-namespaces

# 特定 namespace のみ
secretsvet cluster-scan --namespace myapp

# 特定チェックをスキップ
secretsvet cluster-scan --skip-etcd --skip-rbac

# JSON 出力
secretsvet cluster-scan --output json
```

### 4. 修正提案 (`--fix`)

`scan` コマンドに `--fix` フラグを追加すると、各ルール違反に対して修正済み YAML スニペットを出力します。

```bash
# 静的テンプレートによる修正提案 (無料)
secretsvet scan ./k8s/ --fix

# 日本語で修正提案
secretsvet scan ./k8s/ --fix --fix-lang ja

# Claude API による修正提案 (静的テンプレートがないルール向け)
ANTHROPIC_API_KEY=sk-... secretsvet scan ./k8s/ --fix --fix-llm
```

---

## ルールリファレンス

### SV1xxx — 平文シークレット (マニフェスト)

| ルール ID | 重大度 | 説明 |
|---|---|---|
| SV1010 | HIGH | `env[].value` へのパスワード/トークン/キーの正規表現マッチング |
| SV1020 | HIGH | `env[].value` への高エントロピー文字列検出 |
| SV1030 | HIGH | `args[]` / `command[]` へのシークレット埋め込み |
| SV1040 | HIGH | ConfigMap の `data` への平文シークレット |
| SV1050 | MEDIUM | `envFrom` で Secret 以外のソース (ConfigMap) を参照 |
| SV1060 | HIGH | Secret リソースに base64 デコードして高エントロピーな値が含まれる |
| SV1070 | LOW | Secret に `immutable: true` が設定されていない |
| SV1080 | MEDIUM | namespace をまたいだ Secret 参照 |

### SV2xxx — External Secrets 設定ミス

| ルール ID | 重大度 | 説明 |
|---|---|---|
| SV2010 | HIGH | ExternalSecret のキー参照が不正な形式 |
| SV2020 | HIGH | SecretStore の接続設定の静的検証 |
| SV2030 | MEDIUM | `refreshInterval` が 24h 以上 |
| SV2040 | MEDIUM | `creationPolicy: Merge` による上書きリスク |
| SV2050 | MEDIUM | remoteRef.key の重複・パスのタイポ |
| SV2060 | HIGH | VaultStaticSecret/VaultDynamicSecret のパス設定ミス |
| SV2070 | HIGH | Vault ロールの過剰権限 (wildcard SA, root/admin ポリシー) |
| SV2080 | MEDIUM | VaultDynamicSecret の `leaseRenewalPercent` 未設定 |
| SV2090 | HIGH | IAM ロールのシークレット読み取り権限が過剰 |
| SV2100 | MEDIUM | シークレットの自動ローテーション無効 (`refreshInterval: 0`) |

### SV3xxx — git 履歴漏洩

| ルール ID | 重大度 | 説明 |
|---|---|---|
| SV3010 | MEDIUM | `.gitignore` が `*.env` / `*secret*` などのパターンを含まない |
| SV3020 | HIGH | `.env` / `.env.local` ファイルのコミット検出 |
| SV3030 | HIGH | git 履歴内のシークレットパターン (AWS/GCP/GitHub/Slack/Stripe/Twilio など) |
| SV3040 | HIGH | git 履歴内の高エントロピー文字列 |
| SV3050 | HIGH | Helm `values.yaml` への平文シークレット記載 |

### SV4xxx — etcd / ランタイム設定

| ルール ID | 重大度 | 説明 |
|---|---|---|
| SV4010 | HIGH | etcd 暗号化未設定 / `identity` プロバイダー使用 |
| SV4030 | MEDIUM | Pod の `automountServiceAccountToken` が未設定 |
| SV4040 | MEDIUM | Secret ボリュームが `readOnly: true` なしでマウント |
| SV4050 | HIGH | RBAC ロールが Secret に対して `list`/`watch` 権限を持つ |
| SV4060 | HIGH | `default` ServiceAccount に Secret アクセス権限 |

---

## 出力フォーマット

### TTY (デフォルト)

カラー付きのターミナル出力。ファイルパス・行番号・重大度・メッセージを表示。

```
[HIGH]   deploy.yaml:23  SV1010  env[].value contains a secret: DB_PASSWORD matches password pattern
[MEDIUM] config.yaml:8   SV1040  ConfigMap data contains plaintext secret: API_KEY
```

### JSON

構造化された JSON 出力。パイプ処理や CI/CD での解析に適しています。

```bash
secretsvet scan ./k8s/ --output json | jq '.findings[] | select(.severity == "HIGH")'
```

```json
{
  "version": "0.1.0",
  "findings": [
    {
      "rule_id": "SV1010",
      "severity": "HIGH",
      "file": "deploy.yaml",
      "line": 23,
      "resource_kind": "Deployment",
      "resource_name": "my-app",
      "namespace": "default",
      "message": "env[].value contains a secret: DB_PASSWORD matches password pattern",
      "detail": "env var: DB_PASSWORD, value: s3cr3t..."
    }
  ],
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

### SARIF

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) 形式。GitHub Advanced Security の Code Scanning と統合できます。

```yaml
# .github/workflows/secretsvet.yml
- name: Run SecretsVet
  run: secretsvet scan ./k8s/ --output sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## ホワイトリスト設定

プロジェクトルートに `.secretsvet-ignore` ファイルを作成することで、特定の検出を無視できます。

```
# ルール ID を無視
SV1070

# ファイルグロブを無視
testdata/**
internal/**/*_test.go

# コミットハッシュプレフィックスを無視 (git-scan)
abc123
```

---

## CI/CD 統合

### GitHub Actions

```yaml
name: SecretsVet
on: [push, pull_request]

jobs:
  secretsvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # git-scan には全履歴が必要

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install SecretsVet
        run: go install github.com/SecretsVet/secretsvet@latest

      # マニフェストスキャン
      - name: Scan manifests
        run: secretsvet scan ./k8s/ --exit-code --output sarif > manifest.sarif

      # git 履歴スキャン
      - name: Scan git history
        run: secretsvet git-scan . --exit-code

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: manifest.sarif
        if: always()
```

### pre-commit フック

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretsvet
        name: SecretsVet
        entry: secretsvet scan
        args: ['--exit-code', '--min-severity', 'HIGH']
        language: system
        types: [yaml]
```

---

## ルールID体系

```
SV1xxx  平文シークレット (manifest)
SV2xxx  External Secrets 設定ミス
SV3xxx  git 履歴漏洩
SV4xxx  etcd / ランタイム設定
SV5xxx  RBAC × Secret アクセス (予定)
```

---

## ライセンス

MIT
