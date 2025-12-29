---
sidebar_position: 3
---

# クイックスタート

Security Scanner MCPを5分で始めましょう!

## ステップ1: 基本的なコードスキャン

Claudeにコードをスキャンするよう依頼します:

```
Me: このコードをセキュリティの問題についてスキャンしてください

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;
```

Claudeは`scan-security`ツールを呼び出して、以下を表示します:

```
## ⚠️ セキュリティ脆弱性が見つかりました!

### 🔴 Critical (1件)
- **Google APIキー** (1行目)
  - Google APIキーがソースコードにハードコードされています
  - 💡 修正方法: 環境変数を使用し、APIキー制限を設定

### 🟠 High (2件)
- **テンプレートリテラルSQL** (2行目)
  - SQLクエリがテンプレートリテラルで変数を使用
  - 💡 修正方法: プリペアドステートメントを使用

- **innerHTML代入** (3行目)
  - 動的値がinnerHTMLに代入
  - 💡 修正方法: textContentを使用またはDOMPurifyでサニタイズ
```

## ステップ2: 自動修正提案を取得

```
Me: innerHTMLの脆弱性を修正する方法を教えてください
```

Claudeは`get-fix-suggestion`を呼び出して、以下を提供します:

```typescript
// ❌ 修正前（脆弱）
element.innerHTML = userInput;

// ✅ 修正後（安全）
element.textContent = userInput;

// またはHTMLが必要な場合:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

## ステップ3: IaCファイルをスキャン

```
Me: このDockerfileをセキュリティの問題についてスキャンしてください
```

Claudeは以下でDockerfileを分析します:
- 組み込みスキャナルール
- Trivy（Dockerイメージが利用可能な場合）
- Checkov（Dockerイメージが利用可能な場合）

## ステップ4: 包括的なレポートを生成

```
Me: Mermaidダイアグラムを含む完全なセキュリティレポートを表示してください
```

Claudeは`generate-security-report`を呼び出して、以下を作成します:

- 重大度分布円グラフ
- 脆弱性カテゴリ別分析
- 攻撃シナリオのフローチャート
- GitHub Code Scanning用SARIF形式
- CVE/OWASP詳細情報

## 利用可能なツール

| ツール | 説明 |
|------|-------------|
| `scan-security` | 包括的なセキュリティスキャン - すべてのチェックを実行 |
| `scan-secrets` | ハードコードされたAPIキー、パスワード、トークンを検出 |
| `scan-injection` | SQL/NoSQL/コマンドインジェクションを検出 |
| `scan-xss` | Cross-Site Scriptingのリスクを特定 |
| `scan-crypto` | 暗号化の脆弱性をチェック |
| `scan-auth` | 認証/セッションセキュリティを監査 |
| `scan-path` | ファイル/パスの脆弱性を検出 |
| `scan-dependencies` | 脆弱な依存関係をチェック |
| `scan-iac` | Dockerfile、Kubernetes、Terraformをスキャン |
| `get-fix-suggestion` | 自動生成された修正コードを取得 |
| `generate-security-report` | 包括的なレポートを作成 |
| `scan-in-sandbox` | Docker隔離環境でスキャンを実行 |

## ヒント

1. **ほとんどの場合は`scan-security`を使用** - すべてのスキャナーを一度に実行
2. **特定スキャナを使用** - 特定の領域に焦点を当てたい場合
3. **修正を依頼** - 脆弱性が見つかった後に修正案を聞く
4. **レポートを生成** - ドキュメントやCI/CD統合用
5. **サンドボックスを使用** - 信頼できないコードをスキャンする場合

## 一般的なワークフロー

### ワークフロー1: クイックチェック

```
Me: このコードをセキュリティの問題についてスキャンしてください
[コードを貼り付け]
```

### ワークフロー2: 詳細分析

```
Me: 詳細なレポート付きで包括的なセキュリティスキャンを実行してください
[コードを貼り付け]
```

### ワークフロー3: 安全なスキャン

```
Me: このコードをサンドボックス環境でスキャンしてください
[コードを貼り付け]
```

## 次のステップ

- [基本的な使用方法](./usage/basic-usage.md) - すべてのスキャン機能を学ぶ
- [IaCスキャン](./features/iac-scanning.md) - インフラストラクチャファイルをスキャン
- [サンドボックススキャン](./features/sandbox.md) - Dockerの隔離を使用
