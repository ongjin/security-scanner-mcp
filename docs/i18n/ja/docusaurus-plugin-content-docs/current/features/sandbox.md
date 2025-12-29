---
sidebar_position: 4
---

# Docker サンドボックススキャン

隔離されたDocker環境でセキュリティスキャンを実行して、最大限の安全性を確保します。

## サンドボックスを使用する理由

ホストシステムを潜在的に悪意のあるコードから保護します:
- ✅ **隔離実行** - コンテナ化された環境で実行
- ✅ **リソース制限** - CPU、メモリ、時間の制約
- ✅ **ネットワーク隔離** - 外部ネットワークアクセスなし
- ✅ **読み取り専用ファイルシステム** - ホストファイルを変更できない
- ✅ **強化されたスキャン** - 外部ツール使用（Trivy、Checkov、GitLeaks）

## セットアップ

### Docker Hubから取得（推奨）

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### またはソースからビルド

```bash
npm run docker:build
```

**注**: ビルドには5～10分かかり、約500MBのイメージを作成します。以下を含みます:
- Trivy v0.50.4
- GitLeaks v8.18.4
- Checkov（Pythonベース）

## 使用方法

### 基本的なサンドボックススキャン

```
Me: このコードをサンドボックスでスキャンしてください

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claudeは`scan-in-sandbox`を呼び出して:
1. コードを一時ファイルに書き込み
2. Dockerコンテナを起動
3. コンテナ内ですべてのスキャナーを実行
4. 結果をJSONとして返す
5. コンテナをクリーンアップ

### 信頼できないコードをスキャン

```
Me: このコードは疑わしく見えます。安全にスキャンしてください

[潜在的に悪意のあるコードを貼り付け]
```

## セキュリティ設定

### デフォルト設定

```
メモリ制限: 512MB
CPU制限: 0.5コア
タイムアウト: 30秒
ネットワーク: 無効
ファイルシステム: 読み取り専用（/tmpを除く）
機能: 削除（no-new-privileges）
```

### カスタマイズ可能なオプション

環境変数を通じてこれらを調整できます:

```bash
SANDBOX_MEMORY=1g \
SANDBOX_CPU=1.0 \
SANDBOX_TIMEOUT=60000 \
scan-in-sandbox
```

## サンドボックスで利用可能なスキャナー

### 組み込みスキャナー
- シークレット検出
- SQL/NoSQL/コマンドインジェクション
- XSS脆弱性
- 暗号化の問題
- 認証の問題
- パストラバーサル

### 外部ツール（Dockerのみ）
- **GitLeaks**: エントロピー分析によるシークレット検出の強化
- **Trivy**: IaCおよびコンテナの脆弱性スキャン
- **Checkov**: Infrastructure as Code セキュリティ分析

## Dockerコンテナの詳細

### ベースイメージ
```dockerfile
FROM node:20-alpine
```

### セキュリティハードニング

```dockerfile
# ルート以外のユーザー
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner

# 読み取り専用ルートファイルシステム
# 新しい特権なし
# 削除された機能
# ネットワーク無効
```

### インストールされたツール

```bash
# ツールが インストールされていることを確認
docker run security-scanner-mcp:latest sh -c "
  trivy --version &&
  gitleaks version &&
  checkov --version
"
```

## 結果フォーマット

サンドボックススキャンは包括的なJSONを返します:

```json
{
  "success": true,
  "language": "javascript",
  "filename": "code.js",
  "issuesCount": 3,
  "issues": [
    {
      "type": "Google API Key",
      "severity": "critical",
      "message": "Google APIキーがハードコード",
      "fix": "環境変数を使用",
      "line": 1,
      "metadata": {
        "tool": "gitleaks",
        "ruleId": "google-api-key",
        "entropy": 4.2
      }
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

## パフォーマンス考慮事項

### コンテナ起動
- **初回実行**: 約2～3秒（コールドスタート）
- **後続実行**: 約1秒（キャッシュ）

### スキャン時間
- **小さいファイル（100行未満）**: 5秒未満
- **中程度のファイル（100～500行）**: 5～15秒
- **大きいファイル（500行以上）**: 15～30秒

### リソース使用量
- **メモリ**: スキャンあたり約100～200MB
- **CPU**: 最小（0.1～0.5コア）
- **ディスク**: 一時ファイルは自動的にクリーンアップ

## トラブルシューティング

### コンテナが見つからない

```bash
# イメージが存在するか確認
docker images | grep security-scanner-mcp

# 見つからない場合は取得
docker pull ongjin/security-scanner-mcp:latest
```

### パーミッション拒否

```bash
# ユーザーをdockerグループに追加
sudo usermod -aG docker $USER

# シェルを再起動
```

### タイムアウトの問題

```bash
# タイムアウトを増加（ミリ秒）
SANDBOX_TIMEOUT=60000 scan-in-sandbox
```

## ベストプラクティス

1. **信頼できないコードに使用**: 常に未知のソースからのコードをスキャン
2. **定期的にイメージを更新**: 月単位でセキュリティアップデートを取得
3. **リソース使用量を監視**: 制限により悪用を防止
4. **クリーンアップ**: コンテナは自動削除されますが、定期的にチェック
5. **ネットワーク隔離を維持**: 必要でない限りネットワークを無効のまま

## 高度な設定

### カスタムDockerイメージ

```dockerfile
FROM security-scanner-mcp:latest

# カスタムスキャナーを追加
RUN pip3 install custom-scanner

# カスタムルールを追加
COPY custom-rules.yaml /app/rules/
```

### CI/CD統合

```yaml
# GitHub Actionsの例
- name: Scan Code in Sandbox
  run: |
    docker pull ongjin/security-scanner-mcp:latest
    docker run --rm \
      -v ${{ github.workspace }}:/code:ro \
      security-scanner-mcp:latest \
      scan /code
```

## 次のステップ

- [外部ツール](../advanced/external-tools.md) - Trivy、Checkov、GitLeaksについて学ぶ
- [レポート](../advanced/reporting.md) - SARIFレポートを生成
- [統合](../advanced/integration.md) - CI/CDに統合
