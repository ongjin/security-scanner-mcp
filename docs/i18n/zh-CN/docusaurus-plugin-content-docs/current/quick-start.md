---
sidebar_position: 3
---

# 快速开始

在 5 分钟内快速开始使用 Security Scanner MCP！

## 第 1 步：基本代码扫描

请求 Claude 扫描您的代码：

```
我：扫描此代码以查找安全问题

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;
```

Claude 将调用 `scan-security` 并显示：

```
## ⚠️ 发现安全漏洞！

### 🔴 严重（1 个问题）
- **Google API 密钥**（第 1 行）
  - Google API 密钥在源代码中硬编码
  - 💡 修复：使用环境变量并在 Google Cloud Console 中设置 API 密钥限制

### 🟠 高（2 个问题）
- **模板文字 SQL**（第 2 行）
  - SQL 查询使用带变量的模板文字
  - 💡 修复：使用预处理语句

- **innerHTML 赋值**（第 3 行）
  - 动态值分配给 innerHTML
  - 💡 修复：使用 textContent 或使用 DOMPurify 进行清理
```

## 第 2 步：获取自动修复建议

```
我：展示我如何修复 innerHTML 漏洞
```

Claude 将调用 `get-fix-suggestion` 并提供：

```typescript
// ❌ 之前（易受攻击）
element.innerHTML = userInput;

// ✅ 之后（安全）
element.textContent = userInput;

// 或者如果需要 HTML：
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

## 第 3 步：扫描 IaC 文件

```
我：扫描我的 Dockerfile 以查找安全问题
```

Claude 将使用以下工具分析您的 Dockerfile：
- 内置扫描规则
- Trivy（如果有 Docker 镜像）
- Checkov（如果有 Docker 镜像）

## 第 4 步：生成综合报告

```
我：显示完整的安全报告，包含 Mermaid 图表
```

Claude 将调用 `generate-security-report` 并创建：

- 严重程度分布饼图
- 漏洞类别细分
- 攻击场景流程图
- GitHub Code Scanning 的 SARIF 格式
- CVE/OWASP 详细信息

## 可用工具

| 工具 | 描述 |
|------|------|
| `scan-security` | 综合安全扫描 - 一次性运行所有检查 |
| `scan-secrets` | 检测硬编码的 API 密钥、密码、令牌 |
| `scan-injection` | 查找 SQL/NoSQL/命令注入漏洞 |
| `scan-xss` | 识别跨站脚本风险 |
| `scan-crypto` | 检查密码学弱点 |
| `scan-auth` | 审计身份验证/会话安全 |
| `scan-path` | 查找文件/路径漏洞 |
| `scan-dependencies` | 检查易受攻击的依赖项 |
| `scan-iac` | 扫描 Dockerfile、Kubernetes、Terraform |
| `get-fix-suggestion` | 获取自动生成的修复代码 |
| `generate-security-report` | 创建综合报告 |
| `scan-in-sandbox` | 在 Docker 隔离环境中运行扫描 |

## 提示

1. **大多数情况下使用 `scan-security`** - 它一次运行所有扫描工具
2. **使用特定扫描工具**当您想关注某一特定领域时
3. **查找漏洞后请求修复**
4. **生成报告**用于文档或 CI/CD 集成
5. **使用沙箱**扫描不信任的或可能恶意的代码

## 常见工作流

### 工作流 1：快速检查

```
我：扫描此代码以查找安全问题
[粘贴代码]
```

### 工作流 2：深度分析

```
我：运行全面的安全扫描并生成详细报告
[粘贴代码]
```

### 工作流 3：安全扫描

```
我：在沙箱环境中扫描此代码
[粘贴代码]
```

## 下一步

- [基本用法](./usage/basic-usage.md) - 了解所有扫描功能
- [IaC 扫描](./features/iac-scanning.md) - 扫描基础设施文件
- [沙箱扫描](./features/sandbox.md) - 使用 Docker 隔离
