---
sidebar_position: 1
---

# 介绍

欢迎来到 **Security Scanner MCP** 文档！

## 什么是 Security Scanner MCP?

Security Scanner MCP 是您的**智能安全合作伙伴**，能够自动检测 AI 生成代码中的漏洞并建议修复方案。

研究表明，AI 生成的代码包含的安全漏洞比人工编写的代码多 **322%**。此 MCP 服务器不仅进行简单扫描，还帮助您编写安全的代码。

## 为什么需要这个工具?

AI 代码生成工具功能强大，但经常生成存在安全漏洞的代码。Security Scanner MCP 帮助您：

- 💡 **自动生成修复建议**用于检测到的漏洞
- 🏗️ **扫描 IaC 文件**（Dockerfile、Kubernetes、Terraform）
- 📊 **创建可视化报告**包含 Mermaid 图表和 SARIF 格式
- 🐳 **在 Docker 沙箱中安全运行**以实现隔离
- 🔍 **使用业界标准工具**（Trivy、Checkov、GitLeaks）

## 主要功能

### 代码安全扫描

- 硬编码密钥检测（API 密钥、密码、令牌）
- SQL/NoSQL/命令注入漏洞
- 跨站脚本（XSS）风险
- 密码学弱点
- 身份验证和会话安全问题
- 文件和路径漏洞
- 易受攻击的依赖项

### 基础设施即代码（IaC）扫描

- **Dockerfile**：基于 CIS Docker 基准的 15+ 规则
- **Kubernetes**：基于 Pod 安全标准的 13+ 规则
- **Terraform**：AWS/GCP/Azure 安全的 15+ 规则

### 高级功能

- **自动修复建议**：基于 AST 的代码转换
- **综合报告**：Mermaid 图表 + SARIF + CVE 信息
- **Docker 沙箱**：隔离的扫描环境
- **外部工具**：Trivy、Checkov、GitLeaks 集成

## 快速示例

```typescript
// ❌ 易受攻击的代码
const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

// Claude 检测到：
// 🔴 严重：Google API 密钥硬编码
// 🟠 高：通过模板文字进行 SQL 注入
// 🟠 高：通过 innerHTML 赋值导致 XSS
```

## 下一步

- [安装](./installation.md) - 安装 Security Scanner MCP
- [快速开始](./quick-start.md) - 5 分钟快速开始
- [使用指南](./usage/basic-usage.md) - 了解如何使用所有功能
