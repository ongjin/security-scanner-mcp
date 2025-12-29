---
sidebar_position: 1
---

# 基本用法

了解如何使用 Security Scanner MCP 和 Claude。

## 快速扫描

最简单的扫描代码方法：

```
我：扫描此代码以查找安全问题

const apiKey = "sk_live_1234567890";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claude 将自动调用 `scan-security` 工具并显示结果。

## 扫描结果格式

结果按严重程度组织：

```
## ⚠️ 发现安全漏洞！

### 🔴 严重（1 个问题）
- **Stripe API 密钥**（第 1 行）
  - Stripe Live API 密钥在源代码中硬编码
  - 💡 修复：存储在环境变量中

### 🟠 高（1 个问题）
- **模板文字 SQL**（第 2 行）
  - SQL 查询使用带用户输入的模板文字
  - 💡 修复：使用带占位符的预处理语句
```

## 扫描不同的文件类型

### JavaScript/TypeScript

```
我：检查此 TypeScript 代码

interface User {
  password: string;
}

const user: User = {
  password: "admin123"  // 硬编码密码
};
```

### Python

```
我：扫描此 Python 代码

import os

# 易受攻击
db_password = "mypassword123"
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### Java

```
我：审查此 Java 代码

public class Config {
    private static final String API_KEY = "abc123";

    public void query(String userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
    }
}
```

### Go

```
我：检查此 Go 代码

package main

const apiKey = "sk_test_1234567890"

func query(userId string) {
    sql := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)
}
```

## 扫描基础设施文件

### Dockerfile

```
我：扫描此 Dockerfile

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update
EXPOSE 22
```

### Kubernetes

```
我：检查此 Kubernetes 清单

apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
```

### Terraform

```
我：审查此 Terraform 配置

resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
```

## 理解结果

### 严重程度级别

- 🔴 **严重**：需要立即采取行动（例如，暴露的 API 密钥）
- 🟠 **高**：严重漏洞（例如，SQL 注入）
- 🟡 **中**：重要修复（例如，弱加密）
- 🟢 **低**：应该解决（例如，缺少最佳实践）

### 问题详情

每个问题包括：
- **类型**：漏洞类别
- **行号**：发现位置
- **消息**：问题是什么
- **修复**：如何修复
- **OWASP 类别**：安全分类
- **CWE ID**：通用弱点枚举

## 常见工作流

### 工作流 1：提交前快速检查

```
我：提交前快速安全检查此代码

[粘贴代码]
```

### 工作流 2：深度分析

```
我：进行全面的安全分析

[粘贴代码]

我：展示我如何修复 SQL 注入问题

我：生成完整的安全报告
```

### 工作流 3：基础设施审查

```
我：审查我的 Dockerfile 以查找安全问题

[粘贴 Dockerfile]

我：也检查此 Kubernetes 部署

[粘贴 YAML]
```

### 工作流 4：不受信任的代码

```
我：我在网上找到了此代码，是否安全？

[粘贴代码]

我：在沙箱中扫描它以确保安全
```

## 更好结果的提示

1. **提供上下文**：提及语言/框架
2. **包含足够的代码**：扫描工具需要上下文
3. **请求特定检查**：使用有针对性的工具进行聚焦分析
4. **请求修复**：扫描后询问"我如何修复这个？"
5. **生成报告**：使用 `generate-security-report` 用于文档或 CI/CD 集成

## 误报

如果遇到误报：

```
我：检测到了一个 API 密钥，但实际上是一个占位符

Claude：我理解。扫描工具检测到了该模式，但上下文很重要。
[解释为什么它被标记]
```

## 下一步

- [CLI 用法](./cli.md) - 使用命令行界面
- [MCP 工具](./mcp-tools.md) - 了解所有可用工具
- [自动修复](../features/auto-fix.md) - 获取修复建议
