---
sidebar_position: 2
---

# CLIモード

Claudeなしで独立してSecurity Scanner MCPを実行できます。Jenkins、GitHub Actions、GitLab CIなど、あらゆるCI/CDパイプラインで使用可能です。

## インストール

```bash
# グローバルインストール
npm install -g security-scanner-mcp

# またはnpxを使用（インストール不要）
npx security-scanner-mcp scan ./src
```

## コマンド

### scan

ファイルまたはディレクトリのセキュリティ脆弱性をスキャンします。

```bash
# 単一ファイルをスキャン
security-scanner-mcp scan ./src/app.js

# ディレクトリをスキャン
security-scanner-mcp scan ./src

# 言語を指定
security-scanner-mcp scan ./src --language typescript
```

### serve

MCPサーバーモードで実行します（Claude Desktop/Codeと併用）。

```bash
security-scanner-mcp serve
```

## 出力フォーマット

### Text（デフォルト）

人間が読みやすいカラー出力です。

```bash
security-scanner-mcp scan ./src
```

### JSON

自動化とパース用の機械可読形式です。

```bash
security-scanner-mcp scan ./src --format json
```

出力構造:
```json
{
  "summary": {
    "totalFiles": 10,
    "scannedFiles": 10,
    "totalIssues": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "issues": [
    {
      "file": "./src/app.js",
      "line": 15,
      "severity": "critical",
      "type": "Hardcoded API Key",
      "message": "APIキーがコードにハードコードされています",
      "fix": "環境変数を使用してください"
    }
  ]
}
```

### SARIF

GitHub Code Scanning互換フォーマットです。

```bash
security-scanner-mcp scan ./src --format sarif --output report.sarif
```

## CLIオプション

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `-f, --format` | 出力形式 (text, json, sarif) | text |
| `-o, --output` | 結果をファイルに保存 | - |
| `-l, --language` | プログラミング言語 | auto |
| `-s, --severity` | 最小重大度フィルター | low |
| `--fail-on` | このレベル以上で終了コード1 | critical |
| `--include` | 含めるファイルパターン | *.js,*.ts,*.py,*.java,*.go |
| `--exclude` | 除外するパターン | node_modules,dist,build,.git |
| `--no-color` | カラー出力を無効化 | - |

## CI/CD統合

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g security-scanner-mcp'
                sh 'security-scanner-mcp scan ./src --format json --output security-report.json --fail-on high'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'security-report.json', fingerprint: true
        }
    }
}
```

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run Security Scan
        run: |
          npx security-scanner-mcp scan ./src \
            --format sarif \
            --output results.sarif \
            --fail-on critical

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: security
  image: node:20-alpine
  script:
    - npm install -g security-scanner-mcp
    - security-scanner-mcp scan ./src --format json --output report.json --fail-on high
  artifacts:
    reports:
      security: report.json
```

## 終了コード

| コード | 説明 |
|--------|------|
| 0 | 成功 - `--fail-on`レベル以上の問題なし |
| 1 | 失敗 - `--fail-on`レベル以上の問題が見つかりました |

## 使用例

### TypeScriptファイルのみスキャン

```bash
security-scanner-mcp scan ./src --include "*.ts,*.tsx"
```

### テストファイルを除外

```bash
security-scanner-mcp scan ./src --exclude "*.test.ts,*.spec.ts,__tests__"
```

### High以上の問題でビルドを失敗

```bash
security-scanner-mcp scan ./src --fail-on high
```

## Pre-commitフック

### Huskyを使用

```bash
npm install --save-dev husky
npx husky init
echo 'npx security-scanner-mcp scan ./src --fail-on high' > .husky/pre-commit
```

## Docker使用

```bash
docker pull ongjin/security-scanner-mcp:latest
docker run --rm -v $(pwd):/code:ro ongjin/security-scanner-mcp:latest scan /code/src
```

## 次のステップ

- [MCPツール](./mcp-tools.md) - MCPサーバーツールについて学ぶ
- [統合](../advanced/integration.md) - 高度なCI/CD統合
- [設定](../reference/configuration.md) - 詳細な設定オプション
