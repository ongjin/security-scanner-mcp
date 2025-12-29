---
sidebar_position: 3
---

# CI/CD統合

Security Scanner MCPを開発ワークフローに統合します。

## GitHub Actions

### 基本的なワークフロー

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Node.jsをセットアップ
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Security Scannerをプル
        run: docker pull ongjin/security-scanner-mcp:latest

      - name: コードをスキャン
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code
```

### SARIF付きの高度なワークフロー

```yaml
name: Advanced Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: SARIF付きセキュリティスキャン
        run: |
          docker run --rm \
            -v $(pwd):/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code --format sarif > security.sarif

      - name: SARIFをアップロード
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
          category: security-scanner-mcp
```

## GitLab CI

```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind

  before_script:
    - docker pull ongjin/security-scanner-mcp:latest

  script:
    - docker run --rm -v $(pwd):/code:ro
        ongjin/security-scanner-mcp:latest scan /code

  artifacts:
    reports:
      sast: security-report.json

  only:
    - merge_requests
    - main
```

## Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ongjin/security-scanner-mcp:latest')
                          .inside('-v $WORKSPACE:/code:ro') {
                        sh 'scan /code --format json > security-report.json'
                    }
                }
            }
        }

        stage('Publish Results') {
            steps {
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

## CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: docker:latest

    steps:
      - checkout
      - setup_remote_docker

      - run:
          name: Scannerをプル
          command: docker pull ongjin/security-scanner-mcp:latest

      - run:
          name: スキャンを実行
          command: |
            docker run --rm \
              -v $(pwd):/code:ro \
              ongjin/security-scanner-mcp:latest \
              scan /code

      - store_artifacts:
          path: security-report.json

workflows:
  version: 2
  security:
    jobs:
      - security-scan
```

## Pre-commit フック

### Huskyを使用

```bash
# インストール
npm install --save-dev husky

# セットアップ
npx husky install
npx husky add .husky/pre-commit "npm run security-scan"
```

```json
{
  "scripts": {
    "security-scan": "security-scanner-mcp scan src/"
  }
}
```

### pre-commitフレームワークを使用

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-scan
        name: Security Scanner MCP
        entry: docker run --rm -v $(pwd):/code:ro ongjin/security-scanner-mcp:latest scan
        language: system
        pass_filenames: false
```

## IDE統合

### VS Code

タスクを作成（`.vscode/tasks.json`）:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "docker",
      "args": [
        "run", "--rm",
        "-v", "${workspaceFolder}:/code:ro",
        "ongjin/security-scanner-mcp:latest",
        "scan", "/code/${relativeFile}"
      ],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": []
    }
  ]
}
```

### IntelliJ IDEA

外部ツールを作成:
1. 設定 → ツール → 外部ツール
2. 新しいツールを追加:
   - 名前: Security Scanner
   - プログラム: docker
   - 引数: `run --rm -v $ProjectFileDir$:/code:ro ongjin/security-scanner-mcp:latest scan /code/$FilePath$`

## デプロイメントゲート

### Critical問題でブロック

```yaml
- name: Security Gate
  run: |
    docker run --rm \
      -v $(pwd):/code:ro \
      ongjin/security-scanner-mcp:latest \
      scan /code --fail-on critical

    if [ $? -ne 0 ]; then
      echo "Critical脆弱性が見つかりました!"
      exit 1
    fi
```

### 重大度のしきい値

```bash
# 高または緊急時に失敗
scan --min-severity high

# あらゆる脆弱性で失敗
scan --min-severity low
```

## 通知統合

### Slack

```yaml
- name: Slackに通知
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "セキュリティスキャンに失敗しました!",
        "attachments": [{
          "color": "danger",
          "fields": [{
            "title": "リポジトリ",
            "value": "${{ github.repository }}"
          }]
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### メール

```yaml
- name: メールを送信
  if: failure()
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 465
    username: ${{secrets.MAIL_USERNAME}}
    password: ${{secrets.MAIL_PASSWORD}}
    subject: Security Scanに失敗
    body: ワークフロー実行の詳細を確認してください
```

## メトリクスと追跡

### Prometheus

```yaml
- name: メトリクスをエクスポート
  run: |
    cat <<EOF > metrics.txt
    # HELP security_vulnerabilities 見つかった脆弱性の合計
    # TYPE security_vulnerabilities gauge
    security_vulnerabilities{severity="critical"} $(jq '.summary.critical' report.json)
    security_vulnerabilities{severity="high"} $(jq '.summary.high' report.json)
    EOF
```

### Grafanaダッシュボード

時系列で追跡:
- 脆弱性トレンド
- 修正までの時間
- 重大度分布
- カテゴリ別内訳

## ベストプラクティス

1. **すべてのコミットで実行**: 問題を早期に発見
2. **マージをブロック**: クリーンなスキャンが必要
3. **しきい値を設定**: 受け入れ可能なリスクレベルを定義
4. **メトリクスを追跡**: 改善を監視
5. **修正を自動化**: 可能な場所で自動修復を使用
6. **定期的に更新**: スキャナーとルールを最新に

## トラブルシューティング

### Docker パーミッション問題

```bash
# ユーザーをdockerグループに追加
sudo usermod -aG docker $USER
```

### CI/CD タイムアウト

```yaml
# タイムアウトを増加
timeout-minutes: 30
```

### 大規模なコードベース

```bash
# 段階的にスキャン
git diff --name-only HEAD~1 | xargs security-scanner-mcp scan
```

## 次のステップ

- [レポート](./reporting.md) - 包括的なレポートを生成
- [外部ツール](./external-tools.md) - 強化されたスキャン
- [設定](../reference/configuration.md) - 高度な設定
