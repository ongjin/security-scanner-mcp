---
sidebar_position: 2
---

# コマンドラインインターフェース

コマンドラインからSecurity Scanner MCPを直接使用します。

## インストール

```bash
# グローバルインストール
npm install -g security-scanner-mcp

# またはnpxを使用
npx security-scanner-mcp
```

## 基本的なコマンド

### バージョン情報

```bash
security-scanner-mcp --version
```

### ヘルプ

```bash
security-scanner-mcp --help
```

## スタンドアロン使用

Security Scanner MCPはClaude Codeで動作するように設計されていますが、プログラムで使用することもできます:

```javascript
import { scanSecrets, scanInjection, scanXss } from 'security-scanner-mcp';

const code = `
  const apiKey = "AIzaSyC1234567890";
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
`;

// シークレットをスキャン
const secretIssues = scanSecrets(code);

// インジェクションをスキャン
const injectionIssues = scanInjection(code, 'javascript');

// XSSをスキャン
const xssIssues = scanXss(code, 'javascript');

console.log('合計問題数:', [
  ...secretIssues,
  ...injectionIssues,
  ...xssIssues
].length);
```

## CI/CD統合

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Node.jsをセットアップ
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Security Scannerをインストール
        run: npm install -g security-scanner-mcp

      - name: Security Scanを实行
        run: |
          # すべてのJavaScriptファイルをスキャン
          find . -name "*.js" -not -path "*/node_modules/*" | while read file; do
            echo "Scanning $file"
            # スキャンロジックをここに追加
          done
```

### GitLab CI

```yaml
security-scan:
  image: node:20-alpine
  before_script:
    - npm install -g security-scanner-mcp
  script:
    - echo "Running security scans..."
    # スキャンコマンドを追加
  only:
    - merge_requests
    - main
```

## Docker使用

### Dockerの直接実行

```bash
# イメージを取得
docker pull ongjin/security-scanner-mcp:latest

# ファイルをスキャン
docker run --rm \
  -v $(pwd):/code:ro \
  ongjin/security-scanner-mcp:latest \
  scan /code/myfile.js
```

### Docker Compose

```yaml
version: '3.8'
services:
  security-scanner:
    image: ongjin/security-scanner-mcp:latest
    volumes:
      - ./src:/code:ro
    command: scan /code
```

## 設定ファイル

### .securityscannerrc

プロジェクトルートに設定ファイルを作成:

```json
{
  "exclude": [
    "node_modules/**",
    "dist/**",
    "*.test.js"
  ],
  "severity": {
    "minLevel": "medium"
  },
  "rules": {
    "secrets": true,
    "injection": true,
    "xss": true,
    "crypto": true
  }
}
```

## 環境変数

環境変数で動作を設定:

```bash
# サンドボックス設定
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# スキャナー設定
export SCANNER_VERBOSE=true
export SCANNER_OUTPUT=json
```

## 終了コード

CLIは標準の終了コードを使用します:

- `0`: 脆弱性が見つからない
- `1`: 脆弱性が検出
- `2`: スキャンエラー

スクリプトで使用:

```bash
#!/bin/bash
security-scanner-mcp scan myfile.js
if [ $? -eq 1 ]; then
  echo "脆弱性が見つかりました!"
  exit 1
fi
```

## Pre-commit フック

### Huskyを使用

```bash
# husky をインストール
npm install --save-dev husky

# pre-commit フックを追加
npx husky add .husky/pre-commit "npm run security-scan"
```

```json
// package.json
{
  "scripts": {
    "security-scan": "security-scanner-mcp scan src/"
  }
}
```

## VS Code統合

VS Code タスクを作成（`.vscode/tasks.json`）:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "security-scanner-mcp",
      "args": ["scan", "${file}"],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": []
    }
  ]
}
```

## 次のステップ

- [MCPツール](./mcp-tools.md) - MCPサーバーツールについて学ぶ
- [統合](../advanced/integration.md) - 高度なCI/CD統合
- [設定](../reference/configuration.md) - 詳細な設定オプション
