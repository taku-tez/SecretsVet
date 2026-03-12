# SecretsVet Roadmap

Kubernetes環境における機密情報の漏洩・設定ミスを多層的に検出するセキュリティスキャナー。
manifestの`env`直書きに留まらず、ConfigMap・git履歴・External Secrets・etcd暗号化まで網羅する。

---

## v0.1.0 — 静的マニフェスト検出 (Week 1–2)

**Goal:** YAMLマニフェストからシークレット関連の設定ミスを検出する。

### シークレット直書き検出
- [x] `env[].value` へのパスワード/トークン/キーの正規表現マッチング (SV1010)
- [x] `env[].value` への高エントロピー文字列検出 (SV1020)
- [x] `args[]` / `command[]` へのシークレット埋め込み検出 (SV1030)
- [x] ConfigMap の `data` フィールドへの平文シークレット検出 (SV1040)
- [x] Deployment/StatefulSet の `envFrom` で Secret 以外のソースを参照している場合の警告 (SV1050)

### Secretリソース設定
- [x] `type: Opaque` の Secret に base64 デコードして高エントロピーな値が含まれる検出 (SV1060)
- [x] Secret に `immutable: true` が設定されていない警告 (SV1070)
- [x] namespace をまたいだ Secret 参照の検出 (SV1080)

### サポートフォーマット
- [x] YAML (単一ファイル・複数ドキュメント)
- [x] ディレクトリ再帰スキャン
- [x] Kustomize 対応 (`kustomize build` 後のマニフェスト)

### 出力フォーマット
- [x] TTY (カラー付き)
- [x] JSON
- [x] SARIF

---

## v0.2.0 — External Secrets 検証 (Week 3–4)

**Goal:** External Secrets Operator・Vault・AWS/GCP SM の設定ミスを検出する。

### External Secrets Operator
- [x] `ExternalSecret` / `ClusterExternalSecret` のキー参照が正しい形式か検証 (SV2010)
- [x] `SecretStore` / `ClusterSecretStore` の接続設定の静的検証 (SV2020)
- [x] `refreshInterval` が過度に長い（24h以上）場合の警告 (SV2030)
- [x] `CreationPolicy: Merge` による既存Secretへの意図しない上書きリスク検出 (SV2040)
- [x] 参照先のキーが存在しない可能性のあるパターン検出 (パスの typo など) (SV2050)

### Vault
- [x] `VaultStaticSecret` / `VaultDynamicSecret` のパス設定検証 (SV2060)
- [x] Vault ロールに過剰な権限が付与されているパターンの検出 (SV2070)
- [x] `leaseRenewalPercent` 未設定による期限切れリスク警告 (SV2080)

### AWS Secrets Manager / GCP Secret Manager
- [x] IAM ロールのシークレット読み取り権限が過剰に広い場合の警告 (SV2090)
- [x] シークレットの自動ローテーション設定の有無確認 (SV2100)

---

## v0.3.0 — git 履歴スキャン (Week 5–6)

**Goal:** git リポジトリの履歴に残った機密情報を検出する。

- [x] git log 全コミット履歴のシークレットスキャン (SV3030)
- [x] 削除済みファイルも含めた検出 (--diff-filter=AM)
- [x] `.gitignore` の設定ミス検出（`*.env`, `*secret*` が除外されているか）(SV3010)
- [x] `.env` / `.env.local` ファイルのコミット検出 (SV3020)
- [x] Helm `values.yaml` への平文シークレット記載検出 (SV3050)
- [x] 高エントロピー文字列の検出（Shannonエントロピーベース）(SV3040)
- [x] 既知パターンライブラリ: AWS/GCP/GitHub/Slack/Stripe/Twilio トークン (detector/pattern.go)
- [x] ホワイトリスト設定 (`.secretsvet-ignore`)

---

## v0.4.0 — ライブクラスタースキャン (Week 7–8)

**Goal:** 稼働中クラスターのシークレット設定を検証する。

### etcd暗号化検証
- [x] `--encryption-provider-config` の設定確認 (kubectl経由) (SV4010)
- [x] `EncryptionConfiguration` で `identity` (無暗号化) が使われていないか (SV4010)
- [x] Secret が etcd 上で暗号化されているか (`kubectl get secret -o json` + base64確認) (SV4010)

### ランタイム設定
- [x] `automountServiceAccountToken: false` が適切に設定されているか (SV4030)
- [x] Secret をマウントしている Pod の `readOnly: true` 確認 (SV4040)
- [x] Secret の RBAC 参照範囲 (list/watch は特に危険) の検出 (SV4050)
- [x] `default` ServiceAccount への Secret アクセス権限検出 (SV4060)

### クラスタースキャンオプション
- [x] `secretsvet cluster-scan --context <name>`
- [x] `--namespace` / `--all-namespaces`
- [x] kubeconfig 自動検出 (kubectl が自動使用)

---

## v0.5.0 — LLM修正提案 (Week 9–10)

**Goal:** 検出した問題に対して具体的な修正YAMLを生成する。

- [x] `--fix` フラグで違反ごとに修正済みYAMLスニペットを出力
- [x] `--fix-lang ja` で日本語説明
- [x] Secret → ExternalSecret への移行テンプレート生成 (SV1060 fix)
- [x] 平文値のマスキング後に安全な参照形式へ変換 (valueFrom.secretKeyRef テンプレート)

---

## v0.7.0 — Helm / Kustomize 深堀り (Week 11–12)

**Goal:** テンプレートエンジン経由の漏洩を検出する。

- [x] Helm `values.yaml` / `values-*.yaml` への平文シークレット検出 (SV6010)
- [x] Kustomize `secretGenerator.envs[]` で `.env` ファイルを直接参照する検出 (SV6020)
- [x] Kustomize `secretGenerator.literals[]` への平文シークレット直書き検出 (SV6030)
- [x] Helm 管理 Secret への直接管理警告（values.yaml / --set 経由の漏洩リスク）(SV6040)
- [x] stdin 対応 (`helm template ./chart | secretsvet scan -`)
- [x] 全4ルールに fix templates 追加（英語・日本語）

---

## v0.9.0 — 即効性改善: ベースライン & DXコマンド (Week 15–16)

**Goal:** 既存チームが導入しやすくし、CLIだけで使い方がわかる自己説明的なツールにする。

### A. ベースライン機能
- [x] `--save-baseline <file>` — 現在の findings を baseline として保存
- [x] `--baseline <file>` — 既知の findings を抑制し、新規のみ報告
- [x] フィンガープリント: リソース名・名前空間・RuleID に基づく（行番号変化に不変）
- [x] `internal/baseline/` パッケージ（Load / Save / Filter / Fingerprint）

```bash
# Step 1: 初回導入時に現状を保存
secretsvet scan . --save-baseline .secretsvet-baseline.json

# Step 2: CI では新規のみ fail
secretsvet scan . --baseline .secretsvet-baseline.json --exit-code
```

### B. DXコマンド
- [x] `secretsvet rules` — 全32ルールを表形式で一覧表示
- [x] `secretsvet rules --category git` — カテゴリ絞り込み
- [x] `secretsvet rules --id SV1010` — ルール詳細・Remediation・修正例
- [x] `secretsvet init [path]` — リポジトリを自動検出して `.secretsvet.yaml` を生成
  - Helm chart / Kustomize / テストディレクトリ / .env ファイルを検出
  - `--force` で上書き
- [x] 全32ルールのメタデータ追加 (`internal/rule/metadata.go`)

---

## v0.8.0 — CI/CD統合強化 (Week 13–14)

**Goal:** GitHub Actions ネイティブ統合・PRスコープスキャン・プロジェクト設定ファイル

### v0.8.0-A — GitHub Actions & インクリメンタルスキャン
- [x] `--output github-actions` — `::error` / `::warning` アノテーション形式 (scan & git-scan)
- [x] `git-scan --since <sha>` — PRのベースSHAから差分のみスキャン（フルhistory不要）
- [x] `scan --helm <chartdir>` — `helm template` 実行→出力を自動スキャン

### v0.8.0-B — `.secretsvet.yaml` 設定ファイル
- [x] ルール単位での無効化 (`rules.SV6040.disabled: true`)
- [x] 重大度上書き (`rules.SV1070.severity: HIGH`)
- [x] パスのグロブ除外 (`ignore.paths: ["tests/**"]`)
- [x] エントロピー閾値調整 (`thresholds.entropy_min_length: 24`)
- [x] `--config <path>` でカスタムパス指定

```yaml
# .secretsvet.yaml — example
rules:
  SV6040:
    disabled: true          # Helm管理Secretの警告を抑制
  SV1070:
    severity: HIGH          # immutable警告を重大度アップ

thresholds:
  entropy_min_length: 24    # デフォルト20より厳しく

ignore:
  paths:
    - tests/**
    - "**/*_test.yaml"
```

```yaml
# .github/workflows/secrets.yml — PR annotation example
- name: Scan manifests
  run: |
    secretsvet scan . --output github-actions --exit-code

- name: Scan git history (PR only)
  run: |
    secretsvet git-scan . \
      --since ${{ github.event.pull_request.base.sha }} \
      --output github-actions \
      --exit-code
```

---

## K8sVet 取り込み計画

| バージョン | K8sVet対応 | 内容 |
|---|---|---|
| SecretsVet v0.1.0 完了後 | K8sVet v0.5.0 | `k8svet scan .` に `secretsvet` ランナー追加 |
| SecretsVet v0.4.0 完了後 | K8sVet v0.5.0 | `k8svet scan --cluster` にシークレット検証追加 |
| SecretsVet v0.5.0 完了後 | K8sVet v0.6.0 | `k8svet scan . --fix` に SecretsVet 修正提案を統合 |

```bash
# K8sVet統合後のイメージ
k8svet scan .
# → [SecretsVet]  ./                28 errors (secrets in env: 12, git history: 8, ESO config: 8)

k8svet scan --cluster --all-namespaces
# → [SecretsVet]  cluster://        5 errors (etcd unencrypted, SA token over-exposed x4)
```

### 自動検出ルール (K8sVet detector)
- `.env` / `.env.*` ファイルが存在する → SecretsVet を git スキャンモードで実行
- `ExternalSecret` / `SecretStore` が含まれる YAML → ESO 検証を実行
- `--cluster` モード → etcd 暗号化・SA トークン設定を検証

---

## ルールID体系

```
SV1xxx  平文シークレット (manifest)
SV2xxx  External Secrets 設定ミス
SV3xxx  git 履歴漏洩
SV4xxx  etcd / ランタイム設定
SV5xxx  RBAC × Secret アクセス
```
