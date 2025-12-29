---
sidebar_position: 2
---

# CLI 模式

无需 Claude 即可独立运行 Security Scanner MCP。适用于 Jenkins、GitHub Actions、GitLab CI 等所有 CI/CD 管道。

## 安装

```bash
# 全局安装
npm install -g security-scanner-mcp

# 或使用 npx（无需安装）
npx security-scanner-mcp scan ./src
```

## 命令

### scan

扫描文件或目录的安全漏洞。

```bash
# 扫描单个文件
security-scanner-mcp scan ./src/app.js

# 扫描目录
security-scanner-mcp scan ./src

# 指定语言
security-scanner-mcp scan ./src --language typescript
```

### serve

以 MCP 服务器模式运行（与 Claude Desktop/Code 一起使用）。

```bash
security-scanner-mcp serve
```

## 输出格式

### Text（默认）

人类可读的彩色输出。

```bash
security-scanner-mcp scan ./src
```

### JSON

用于自动化和解析的机器可读格式。

```bash
security-scanner-mcp scan ./src --format json
```

输出结构:
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
      "message": "API 密钥被硬编码在代码中",
      "fix": "请使用环境变量"
    }
  ]
}
```

### SARIF

GitHub Code Scanning 兼容格式。

```bash
security-scanner-mcp scan ./src --format sarif --output report.sarif
```

## CLI 选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-f, --format` | 输出格式 (text, json, sarif) | text |
| `-o, --output` | 将结果保存到文件 | - |
| `-l, --language` | 编程语言 | auto |
| `-s, --severity` | 最低严重级别过滤 | low |
| `--fail-on` | 达到此级别时退出代码为 1 | critical |
| `--include` | 要包含的文件模式 | *.js,*.ts,*.py,*.java,*.go |
| `--exclude` | 要排除的模式 | node_modules,dist,build,.git |
| `--no-color` | 禁用彩色输出 | - |

## CI/CD 集成

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

## 退出代码

| 代码 | 说明 |
|------|------|
| 0 | 成功 - 没有 `--fail-on` 级别以上的问题 |
| 1 | 失败 - 发现 `--fail-on` 级别以上的问题 |

## 使用示例

### 仅扫描 TypeScript 文件

```bash
security-scanner-mcp scan ./src --include "*.ts,*.tsx"
```

### 排除测试文件

```bash
security-scanner-mcp scan ./src --exclude "*.test.ts,*.spec.ts,__tests__"
```

### High 级别以上时构建失败

```bash
security-scanner-mcp scan ./src --fail-on high
```

## Pre-commit 钩子

### 使用 Husky

```bash
npm install --save-dev husky
npx husky init
echo 'npx security-scanner-mcp scan ./src --fail-on high' > .husky/pre-commit
```

## Docker 使用

```bash
docker pull ongjin/security-scanner-mcp:latest
docker run --rm -v $(pwd):/code:ro ongjin/security-scanner-mcp:latest scan /code/src
```

## 下一步

- [MCP 工具](./mcp-tools.md) - 了解 MCP 服务器工具
- [集成](../advanced/integration.md) - 高级 CI/CD 集成
- [配置](../reference/configuration.md) - 详细的配置选项
