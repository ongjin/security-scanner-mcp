---
sidebar_position: 1
---

# はじめに

**Security Scanner MCP**のドキュメントへようこそ!

## Security Scanner MCPとは?

Security Scanner MCPは、AI生成コード内の脆弱性を自動的に検出し、修正提案を行う**インテリジェントなセキュリティパートナー**です。

調査によると、AI生成コードはヒューマンライティングコードと比べて**322%以上のセキュリティ脆弱性**を含んでいます。このMCPサーバーは単純なスキャンを超えて、セキュアなコード作成をサポートします。

## なぜ必要なのか?

AIコード生成ツールは強力ですが、セキュリティ脆弱性を含むコードを生成することが多いです。Security Scanner MCPがお手伝いします:

- 💡 **自動修正提案** - 検出された脆弱性の修正案を自動生成
- 🏗️ **IaCファイルスキャン** - Dockerfile、Kubernetes、Terraformなどをスキャン
- 📊 **ビジュアルレポート** - MermaidダイアグラムとSARIF形式で作成
- 🐳 **Dockerサンドボックス実行** - 隔離環境での安全なスキャン
- 🔍 **業界標準ツール統合** - Trivy、Checkov、GitLeaksを使用

## 主な機能

### コードセキュリティスキャン

- ハードコードされたシークレット検出（APIキー、パスワード、トークン）
- SQL/NoSQL/コマンドインジェクション脆弱性
- Cross-Site Scripting（XSS）リスク
- 暗号化の脆弱性
- 認証とセッションセキュリティの問題
- ファイルとパスの脆弱性
- 脆弱な依存関係

### インフラストラクチャ・アズ・コード（IaC）スキャン

- **Dockerfile**: CIS Dockerベンチマークに基づく15以上のルール
- **Kubernetes**: ポッドセキュリティ標準に基づく13以上のルール
- **Terraform**: AWS/GCP/Azureセキュリティの15以上のルール

### 高度な機能

- **自動修正提案**: AST ベースのコード変換
- **包括的なレポート**: Mermaidダイアグラム + SARIF + CVE情報
- **Dockerサンドボックス**: 隔離されたスキャン環境
- **外部ツール統合**: Trivy、Checkov、GitLeaksの統合

## クイック例

```typescript
// ❌ 脆弱なコード
const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

// Claudeが検出:
// 🔴 Critical: Google APIキーがハードコード
// 🟠 High: テンプレートリテラルによるSQL インジェクション
// 🟠 High: innerHTMLへの代入によるXSS
```

## 次のステップ

- [インストール](./installation.md) - Security Scanner MCPをインストール
- [クイックスタート](./quick-start.md) - 5分で始める
- [使用ガイド](./usage/basic-usage.md) - すべての機能を学ぶ
