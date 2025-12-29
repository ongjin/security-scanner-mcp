---
sidebar_position: 2
---

# インストール

## npmからインストール（推奨）

```bash
npm install -g security-scanner-mcp
```

## またはソースからビルド

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## Claude Codeに登録

### グローバルnpmインストール後

```bash
claude mcp add --scope project security-scanner -- security-scanner-mcp
```

### またはソースからビルドした場合

```bash
claude mcp add --scope project security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## クイックセットアップ（自動承認）

毎回ツール使用を承認するのが面倒な場合は、自動承認を設定してください:

### 🖥️ Claude Desktopアプリユーザー

1. Claudeアプリを再起動します。
2. `security-scanner`ツールを使用する質問をします。
3. 通知が表示されたら、**「このサーバーからのリクエストを常に許可」**をチェックして**許可**をクリックします。

### ⌨️ Claude Code（CLI）ユーザー

1. ターミナルで`claude`を実行します。
2. プロンプトで`/permissions`と入力してEnterを押します。
3. **グローバルパーミッション**（またはプロジェクトパーミッション）> **許可されたツール**を選択します。
4. メインツールだけの場合は`mcp__security-scanner__scan-security`、すべてのツールを許可する場合は`mcp__security-scanner__*`を入力します。

> 💡 **ヒント**: ほとんどの場合、**`scan-security`**だけを許可するで十分です。すべてのセキュリティチェックが一度に実行されます。

## Dockerセットアップ（オプション）

サンドボックススキャンの場合、Dockerが必要です:

### Docker Hubから取得（推奨）

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### またはソースからビルド

```bash
npm run docker:build
```

> 注: ビルドには5～10分かかり、イメージサイズは約500MBです。

Dockerイメージには以下が含まれています:
- **Trivy v0.50.4** - コンテナ/IaC脆弱性スキャナー
- **GitLeaks v8.18.4** - シークレット検出
- **Checkov** - Infrastructure as Code セキュリティスキャナー

## インストール確認

```bash
# 正しくインストールされたか確認
security-scanner-mcp --version

# またはソースからビルドした場合
node dist/index.js --version
```

## システム要件

- **Node.js**: >= 18.0.0
- **npm**: >= 9.0.0
- **Docker**（オプション、サンドボックススキャン用）

## 次のステップ

- [クイックスタート](./quick-start.md) - 5分で始める
- [基本的な使用方法](./usage/basic-usage.md) - コードのスキャン方法を学ぶ
