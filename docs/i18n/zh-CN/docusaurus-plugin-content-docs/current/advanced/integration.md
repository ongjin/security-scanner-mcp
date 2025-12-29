---
sidebar_position: 3
---

# CI/CD 集成

将 Security Scanner MCP 集成到您的开发工作流中。

## GitHub Actions

### 基本工作流

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

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Pull Security Scanner
        run: docker pull ongjin/security-scanner-mcp:latest

      - name: Scan Code
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code
```

### 带 SARIF 的高级工作流

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

      - name: Security Scan with SARIF
        run: |
          docker run --rm \
            -v $(pwd):/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code --format sarif > security.sarif

      - name: Upload SARIF
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
          name: Pull Scanner
          command: docker pull ongjin/security-scanner-mcp:latest

      - run:
          name: Run Scan
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

## 预提交钩子

### 使用 Husky

```bash
# 安装
npm install --save-dev husky

# 设置
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

### 使用预提交框架

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

## IDE 集成

### VS Code

在 `.vscode/tasks.json` 中创建任务：

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

创建外部工具：
1. 设置 → 工具 → 外部工具
2. 添加新工具：
   - 名称：Security Scanner
   - 程序：docker
   - 参数：`run --rm -v $ProjectFileDir$:/code:ro ongjin/security-scanner-mcp:latest scan /code/$FilePath$`

## 部署门卫

### 阻止严重问题

```yaml
- name: Security Gate
  run: |
    docker run --rm \
      -v $(pwd):/code:ro \
      ongjin/security-scanner-mcp:latest \
      scan /code --fail-on critical

    if [ $? -ne 0 ]; then
      echo "发现严重漏洞！"
      exit 1
    fi
```

### 严重程度阈值

```bash
# 高或严重时失败
scan --min-severity high

# 任何漏洞时失败
scan --min-severity low
```

## 通知集成

### Slack

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "安全扫描失败！",
        "attachments": [{
          "color": "danger",
          "fields": [{
            "title": "Repository",
            "value": "${{ github.repository }}"
          }]
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 电子邮件

```yaml
- name: Send Email
  if: failure()
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 465
    username: ${{secrets.MAIL_USERNAME}}
    password: ${{secrets.MAIL_PASSWORD}}
    subject: 安全扫描失败
    body: 检查工作流运行以获取详细信息
```

## 指标和跟踪

### Prometheus

```yaml
- name: Export Metrics
  run: |
    cat <<EOF > metrics.txt
    # HELP security_vulnerabilities 发现的总漏洞数
    # TYPE security_vulnerabilities gauge
    security_vulnerabilities{severity="critical"} $(jq '.summary.critical' report.json)
    security_vulnerabilities{severity="high"} $(jq '.summary.high' report.json)
    EOF
```

### Grafana 仪表板

跟踪：
- 漏洞趋势
- 修复时间
- 严重程度分布
- 类别细分

## 最佳实践

1. **每次提交都运行**：尽早捕获问题
2. **阻止合并**：要求干净的扫描
3. **设置阈值**：定义可接受的风险级别
4. **跟踪指标**：监控改进
5. **自动修复**：在可能的情况下使用自动补救
6. **定期更新**：保持扫描工具和规则当前

## 故障排除

### Docker 权限问题

```bash
# 将用户添加到 docker 组
sudo usermod -aG docker $USER
```

### CI/CD 超时

```yaml
# 增加超时
timeout-minutes: 30
```

### 大型代码库

```bash
# 增量扫描
git diff --name-only HEAD~1 | xargs security-scanner-mcp scan
```

## 下一步

- [报告](./reporting.md) - 生成综合报告
- [外部工具](./external-tools.md) - 增强扫描
- [配置](../reference/configuration.md) - 高级设置
