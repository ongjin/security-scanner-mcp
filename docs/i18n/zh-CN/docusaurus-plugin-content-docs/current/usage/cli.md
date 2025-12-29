---
sidebar_position: 2
---

# 命令行界面

直接从命令行使用 Security Scanner MCP。

## 安装

```bash
# 全局安装
npm install -g security-scanner-mcp

# 或使用 npx
npx security-scanner-mcp
```

## 基本命令

### 版本信息

```bash
security-scanner-mcp --version
```

### 帮助

```bash
security-scanner-mcp --help
```

## 独立使用

虽然 Security Scanner MCP 设计用于 Claude Code，但您也可以以编程方式使用它：

```javascript
import { scanSecrets, scanInjection, scanXss } from 'security-scanner-mcp';

const code = `
  const apiKey = "AIzaSyC1234567890";
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
`;

// 扫描密钥
const secretIssues = scanSecrets(code);

// 扫描注入
const injectionIssues = scanInjection(code, 'javascript');

// 扫描 XSS
const xssIssues = scanXss(code, 'javascript');

console.log('总问题数:', [
  ...secretIssues,
  ...injectionIssues,
  ...xssIssues
].length);
```

## CI/CD 集成

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Security Scanner
        run: npm install -g security-scanner-mcp

      - name: Run Security Scan
        run: |
          # 扫描所有 JavaScript 文件
          find . -name "*.js" -not -path "*/node_modules/*" | while read file; do
            echo "Scanning $file"
            # 您的扫描逻辑在这里
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
    # 添加您的扫描命令
  only:
    - merge_requests
    - main
```

## Docker 使用

### 直接 Docker 运行

```bash
# 拉取镜像
docker pull ongjin/security-scanner-mcp:latest

# 扫描文件
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

## 配置文件

### .securityscannerrc

在您的项目根目录创建配置文件：

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

## 环境变量

使用环境变量配置行为：

```bash
# 沙箱设置
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# 扫描工具设置
export SCANNER_VERBOSE=true
export SCANNER_OUTPUT=json
```

## 退出代码

CLI 使用标准退出代码：

- `0`：未发现漏洞
- `1`：检测到漏洞
- `2`：扫描错误

在脚本中使用：

```bash
#!/bin/bash
security-scanner-mcp scan myfile.js
if [ $? -eq 1 ]; then
  echo "发现漏洞！"
  exit 1
fi
```

## 预提交钩子

### 使用 Husky

```bash
# 安装 husky
npm install --save-dev husky

# 添加预提交钩子
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

## VS Code 集成

创建 VS Code 任务（`.vscode/tasks.json`）：

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

## 下一步

- [MCP 工具](./mcp-tools.md) - 了解 MCP 服务器工具
- [集成](../advanced/integration.md) - 高级 CI/CD 集成
- [配置](../reference/configuration.md) - 详细的配置选项
