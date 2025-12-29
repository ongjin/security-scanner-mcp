---
sidebar_position: 1
---

# 外部セキュリティツール

Security Scanner MCPと統合された業界標準ツールについて学びます。

## 概要

Dockerサンドボックスモードで実行する場合、Security Scanner MCPは3つの強力な外部ツールを活用して検出機能を強化します:

- **Trivy** - コンテナおよびIaC脆弱性スキャナー
- **Checkov** - Infrastructure as Code セキュリティ分析
- **GitLeaks** - エントロピー分析によるシークレット検出

## Trivy

### 概要

- **バージョン**: 0.50.4
- **開発元**: Aqua Security
- **ライセンス**: Apache 2.0
- **ウェブサイト**: https://trivy.dev

### 機能

**コンテナスキャン**:
- OSパッケージの脆弱性
- アプリケーション依存関係
- 既知のCVE

**IaCスキャン**:
- Dockerfileのミスコンフィグレーション
- Kubernetesマニフェスト
- Terraform/CloudFormation

**機能**:
- 包括的なCVEデータベース
- 高速なスキャン（数秒）
- 複数の出力形式
- エアギャップ対応

### 統合

Trivyは`scan-in-sandbox`を使用する場合、IaCファイルに対して自動的に実行されます:

```
Me: このDockerfileをサンドボックスでスキャンしてください

FROM node:latest
ENV SECRET="abc123"
```

結果には以下を含むTrivyの検出結果が含まれます:
- CVE識別子
- CVSSスコア
- 修正バージョン
- 参考資料

### 設定

カスタムTrivyスキャン:

```bash
# 重大度フィルタリング
docker run security-scanner-mcp trivy --severity HIGH,CRITICAL

# 修正されていない脆弱性をスキップ
docker run security-scanner-mcp trivy --ignore-unfixed
```

## Checkov

### 概要

- **開発元**: Bridgecrew（Palo Alto Networks）
- **ライセンス**: Apache 2.0
- **ウェブサイト**: https://www.checkov.io

### 機能

**サポートされるフレームワーク**:
- Terraform
- CloudFormation
- Kubernetes
- Dockerfile
- Azure ARMテンプレート
- Helmチャート

**ポリシーカバレッジ**:
- 1000以上の組み込みポリシー
- CISベンチマーク
- PCI-DSS
- HIPAA
- SOC 2

**機能**:
- グラフベースのスキャン
- カスタムポリシーサポート
- 修正提案
- 抑制コメント

### 統合

Checkovは IaCファイルに対して自動的にスキャンします:

```
Me: このTerraformファイルをチェックしてください

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # 暗号化がない
}
```

結果に含まれるもの:
- ポリシーID（CKV_AWS_*）
- ガイドラインリンク
- 修正提案
- コンプライアンスマッピング

### カスタムポリシー

Checkovカスタムポリシーを追加:

```python
# custom_policy.py
from checkov.common.models.enums import CheckResult

class CustomCheck(BaseResourceCheck):
    def scan_resource_conf(self, conf):
        # カスタムロジック
        return CheckResult.PASSED
```

## GitLeaks

### 概要

- **バージョン**: 8.18.4
- **開発元**: Zachary Rice
- **ライセンス**: MIT
- **ウェブサイト**: https://github.com/gitleaks/gitleaks

### 機能

**検出方法**:
- 正規表現パターン
- エントロピー分析
- シャノンエントロピー
- ファイルパススキャン

**サポートされるシークレット**:
- APIキー（1000以上のサービス）
- 秘密鍵
- トークンとパスワード
- 接続文字列
- クラウド認証情報

**機能**:
- 誤検知が少ない
- 高速なスキャン
- カスタムルールサポート
- JSON/SARIF出力

### 統合

GitLeaksはシークレット検出を強化します:

```javascript
// 組み込みスキャナーはパターンを検出
const apiKey = "AIzaSyC123...";

// GitLeaksが追加で提供:
// - エントロピースコア（4.2）
// - ルールID（google-api-key）
// - 信頼度（高）
```

### カスタムルール

GitLeaksカスタムルールを追加:

```toml
# .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''custom_[0-9a-zA-Z]{32}'''
tags = ["api", "custom"]
```

## パフォーマンス比較

| ツール | 速度 | 精度 | カバレッジ |
|------|-------|----------|----------|
| 組み込みスキャナー | ⚡⚡⚡ 非常に高速 | ⭐⭐⭐ 良好 | ⭐⭐ 中程度 |
| GitLeaks | ⚡⚡ 高速 | ⭐⭐⭐⭐ 優秀 | ⭐⭐⭐ 広範 |
| Trivy | ⚡⚡ 高速 | ⭐⭐⭐⭐ 優秀 | ⭐⭐⭐⭐ 包括的 |
| Checkov | ⚡ 中程度 | ⭐⭐⭐⭐ 優秀 | ⭐⭐⭐⭐ 包括的 |

## ベストプラクティス

### 外部ツールをいつ使用するか

✅ **サンドボックス + 外部ツールを使用**:
- 本番コードレビュー
- 配置前のスキャン
- コンプライアンス要件
- 不明/信頼できないコード

⚡ **組み込みスキャナーを使用**:
- 開発中のクイックチェック
- IDE統合
- 即座のフィードバック
- オフラインスキャン

### 最適化ヒント

1. **Dockerイメージをキャッシュ**: 一度取得して何度も使用
2. **並列スキャン**: ツールを同時に実行
3. **結果をフィルタリング**: 高/緊急重大度に焦点を当てる
4. **定期的に更新**: 新しいルールとCVEが月単位で追加

### セキュリティ考慮事項

すべての外部ツールは隔離されたDockerコンテナで実行されます:
- ✅ 読み取り専用ファイルシステム
- ✅ ネットワークアクセスなし
- ✅ 制限されたCPU/メモリ
- ✅ 新しい特権なし
- ✅ 削除された機能

## アップデート

### バージョンを確認

```bash
docker run security-scanner-mcp sh -c "
  trivy --version
  gitleaks version
  checkov --version
"
```

### ツールを更新

```bash
# 更新されたツール付きの最新イメージを取得
docker pull ongjin/security-scanner-mcp:latest
```

## ツール出力の例

### Trivyの出力

```json
{
  "Type": "dockerfile",
  "ID": "CIS-DI-0001",
  "Title": "コンテナ用ユーザーを作成",
  "Severity": "HIGH",
  "Resolution": "USER命令を追加"
}
```

### Checkovの出力

```json
{
  "check_id": "CKV_AWS_18",
  "check_name": "S3バケットがサーバー側暗号化を備えていることを確認",
  "severity": "HIGH",
  "guideline": "https://..."
}
```

### GitLeaksの出力

```json
{
  "Description": "Google API Key",
  "RuleID": "google-api-key",
  "Entropy": 4.2,
  "Match": "AIza...abc",
  "Secret": "AIzaSyC1234567890abcdef"
}
```

## 次のステップ

- [レポート](./reporting.md) - 包括的なレポートを生成
- [統合](./integration.md) - CI/CD統合
- [サンドボックス](../features/sandbox.md) - Docker隔離について学ぶ
