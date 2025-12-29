---
sidebar_position: 2
---

# 安装

## 从 npm 安装（推荐）

```bash
npm install -g security-scanner-mcp
```

## 或从源代码构建

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## 向 Claude Code 注册

### 全局 npm 安装后

```bash
claude mcp add --scope project security-scanner -- security-scanner-mcp
```

### 或从源代码构建

```bash
claude mcp add --scope project security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## 快速设置（自动批准工具）

如果您觉得每次都批准工具使用很麻烦，请设置自动批准：

### 🖥️ Claude Desktop 应用用户

1. 重启 Claude 应用。
2. 提出一个使用 `security-scanner` 工具的问题。
3. 当通知出现时，勾选**"始终允许来自此服务器的请求"**并单击**允许**。

### ⌨️ Claude Code（CLI）用户

1. 在终端中运行 `claude`。
2. 在提示符中输入 `/permissions` 并按 Enter。
3. 选择**全局权限**（或项目权限）> **允许的工具**。
4. 输入 `mcp__security-scanner__scan-security` 仅用于主要工具，或 `mcp__security-scanner__*` 允许所有工具。

> 💡 **提示**：在大多数情况下，仅允许 **`scan-security`** 就足够了，因为它一次性执行所有安全检查。

## Docker 设置（可选）

对于沙箱扫描，您需要 Docker：

### 从 Docker Hub 拉取（推荐）

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### 或从源代码构建

```bash
npm run docker:build
```

> 注意：构建需要 5-10 分钟，镜像大小约为 500MB。

Docker 镜像包含：
- **Trivy v0.50.4** - 容器/IaC 漏洞扫描工具
- **GitLeaks v8.18.4** - 密钥检测工具
- **Checkov** - 基础设施即代码安全扫描工具

## 验证安装

```bash
# 检查是否正确安装
security-scanner-mcp --version

# 或从源代码构建
node dist/index.js --version
```

## 系统要求

- **Node.js**：>= 18.0.0
- **npm**：>= 9.0.0
- **Docker**（可选，用于沙箱扫描）

## 下一步

- [快速开始](./quick-start.md) - 5 分钟快速开始
- [基本用法](./usage/basic-usage.md) - 了解如何扫描代码
