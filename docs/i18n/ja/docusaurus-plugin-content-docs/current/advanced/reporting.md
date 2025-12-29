---
sidebar_position: 2
---

# セキュリティレポート

ダイアグラムと業界標準形式を使用して、包括的なセキュリティレポートを生成します。

## レポートタイプ

### Markdownレポート

人間が読める テキスト形式で、以下を含みます:
- エグゼクティブサマリー
- 重大度の内訳
- 詳細な検出結果
- 修復ガイダンス

### Mermaidダイアグラム

ビジュアル表現:
- **円グラフ**: 重大度分布
- **棒グラフ**: 脆弱性カテゴリ
- **フローチャート**: 攻撃シナリオ

### SARIF形式

静的分析結果交換形式:
- GitHub Code Scanning互換
- VS Code統合
- CI/CDツールサポート

## generate-security-reportツール

### 使用方法

```
Me: 包括的なセキュリティレポートを生成してください

[コードまたはスキャン結果]
```

### 出力例

```markdown
# 🛡️ セキュリティスキャンダッシュボード

## 📊 全体的なサマリー

**合計脆弱性数**: 8

| 重大度 | 数 | パーセンテージ |
|----------|-------|------------|
| 🔴 Critical | 2 | 25% |
| 🟠 High | 3 | 37.5% |
| 🟡 Medium | 2 | 25% |
| 🟢 Low | 1 | 12.5% |

## 🎯 重大度分布

\```mermaid
pie title 重大度別脆弱性分布
    "🔴 Critical" : 2
    "🟠 High" : 3
    "🟡 Medium" : 2
    "🟢 Low" : 1
\```

## 📦 脆弱性カテゴリ

\```mermaid
%%{init: {'theme':'base'}}%%
bar title カテゴリ別脆弱性
    x-axis [Secrets, Injection, XSS, Crypto, Auth]
    y-axis "数" 0 --> 5
    bar [2, 2, 1, 1, 2]
\```

## ⚔️ 潜在的な攻撃シナリオ

\```mermaid
flowchart TD
    Start([攻撃者]) --> Recon[偵察]
    Recon --> Secrets[ハードコード<br/>シークレット発見]
    Secrets --> Access[認証<br/>バイパス]
    Access --> Exploit[SQLインジェクション<br/>悪用]
    Exploit --> Data[データ<br/>流出]
    Data --> Impact[ビジネス<br/>影響]
\```

## 🔴 緊急の問題

### 1. ハードコードされたAWS認証情報
- **ファイル**: config.js
- **行**: 12
- **CWE**: CWE-798
- **OWASP**: A07:2021
- **修正**: AWS SDKでIAMロールを使用

## 🟠 高重大度の問題

[詳細な検出結果...]

## 📋 SARIFレポート

GitHub Code Scanning、VS Code、その他のツールと互換性のあるSARIF JSON。

\```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Security Scanner MCP",
        "version": "1.0.0"
      }
    },
    "results": [...]
  }]
}
\```
```

## CVE/OWASP統合

レポートに含まれるもの:

### CVE情報
- CVE ID
- CVSSスコア
- 影響を受けるバージョン
- 修正バージョン
- 参考資料

### OWASP Top 10マッピング
- A01:2021 - Broken Access Control
- A02:2021 - 暗号化の失敗
- A03:2021 - インジェクション
- A04:2021 - 安全でない設計
- A05:2021 - セキュリティミスコンフィグレーション
- A06:2021 - 脆弱で古いコンポーネント
- A07:2021 - 認証と認可の失敗
- A08:2021 - ソフトウェアとデータの整合性の失敗
- A09:2021 - セキュリティログと監視の失敗
- A10:2021 - Server-Side Request Forgery

## GitHub統合

### Code Scanning Alerts

GitHubにSARIFをアップロード:

```bash
# SARIFを生成
curl -X POST https://api.github.com/repos/OWNER/REPO/code-scanning/sarifs \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d @report.sarif.json
```

### Actions統合

```yaml
- name: Security Scan
  run: |
    # SARIFレポートを生成
    # GitHubにアップロード

- name: SARIFをアップロード
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-report.sarif
    category: security-scanner-mcp
```

## レポートのカスタマイズ

### 重大度でフィルタリング

```
Me: 緊急および高重大度の問題のみを表示するレポートを生成してください
```

### カテゴリにフォーカス

```
Me: インジェクション脆弱性に焦点を当てたレポートを作成してください
```

### 修復を含める

```
Me: 詳細な修正手順付きのレポートを生成してください
```

## エクスポート形式

### JSON

```json
{
  "timestamp": "2024-01-20T10:30:00Z",
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  },
  "issues": [...]
}
```

### CSV

```csv
Type,Severity,File,Line,Message,Fix
"SQL Injection","high","api.js",45,"テンプレートリテラルSQL","プリペアドステートメントを使用"
```

### HTML

インタラクティブなHTMLレポート:
- ソート可能なテーブル
- フィルタリング可能な結果
- クリック可能なリファレンス
- レスポンシブデザイン

## ベストプラクティス

1. **定期的に生成**: 主なコード変更後
2. **トレンドを追跡**: 時系列でレポートを比較
3. **チームと共有**: コードレビューに含める
4. **CI/CD統合**: 自動レポート生成
5. **修正を記録**: 解決に応じてレポートを更新

## レポートテンプレート

### エグゼクティブサマリーテンプレート

```markdown
# セキュリティ評価レポート

**プロジェクト**: [名前]
**日付**: [日付]
**スキャン元**: Security Scanner MCP

## エグゼクティブサマリー

本評価では、[X]ファイルにわたって[Y]個のセキュリティ脆弱性が特定されました。
[Z]個の緊急の問題に対してはただちに対応が必要です。

## 主要な検出結果

1. [検出結果1]
2. [検出結果2]
3. [検出結果3]

## 推奨事項

1. [推奨事項1]
2. [推奨事項2]
```

### 技術レポートテンプレート

```markdown
# 技術セキュリティ分析

## 方法論
- 静的分析
- パターンマッチング
- 外部ツール統合（Trivy、Checkov、GitLeaks）

## スコープ
- [スキャンされたファイル]
- [分析された言語]
- [適用されたルールセット]

## 詳細な検出結果
[技術的な詳細...]
```

## 次のステップ

- [統合](./integration.md) - CI/CD統合
- [外部ツール](./external-tools.md) - 強化されたスキャン
- [設定](../reference/configuration.md) - レポートのカスタマイズ
