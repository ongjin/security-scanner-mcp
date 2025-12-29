---
sidebar_position: 1
---

# 外部安全工具

了解与 Security Scanner MCP 集成的业界标准工具。

## 概述

在 Docker 沙箱模式下运行时，Security Scanner MCP 利用三个强大的外部工具来增强检测能力：

- **Trivy** - 容器和 IaC 漏洞扫描工具
- **Checkov** - 基础设施即代码安全分析
- **GitLeaks** - 包含熵分析的密钥检测

## Trivy

### 关于

- **版本**：0.50.4
- **开发者**：Aqua Security
- **许可证**：Apache 2.0
- **网站**：https://trivy.dev

### 功能

**容器扫描**：
- OS 包漏洞
- 应用依赖项
- 已知 CVE

**IaC 扫描**：
- Dockerfile 配置错误
- Kubernetes 清单
- Terraform/CloudFormation

**功能**：
- 综合 CVE 数据库
- 快速扫描（秒级）
- 多种输出格式
- 离线支持

### 集成

使用 `scan-in-sandbox` 时，Trivy 自动为 IaC 文件运行：

```
我：在沙箱中扫描此 Dockerfile

FROM node:latest
ENV SECRET="abc123"
```

结果包括带有以下内容的 Trivy 发现：
- CVE 标识符
- CVSS 分数
- 修复版本
- 参考资料

### 配置

自定义 Trivy 扫描：

```bash
# 严重程度过滤
docker run security-scanner-mcp trivy --severity HIGH,CRITICAL

# 跳过未修复的漏洞
docker run security-scanner-mcp trivy --ignore-unfixed
```

## Checkov

### 关于

- **开发者**：Bridgecrew（Palo Alto Networks）
- **许可证**：Apache 2.0
- **网站**：https://www.checkov.io

### 功能

**支持的框架**：
- Terraform
- CloudFormation
- Kubernetes
- Dockerfile
- Azure ARM 模板
- Helm 图表

**策略覆盖**：
- 1000+ 内置策略
- CIS 基准
- PCI-DSS
- HIPAA
- SOC 2

**功能**：
- 基于图形的扫描
- 自定义策略支持
- 修复建议
- 抑制注释

### 集成

Checkov 自动扫描 IaC 文件：

```
我：检查此 Terraform 文件

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # 缺少加密
}
```

结果包括：
- 策略 ID（CKV_AWS_*）
- 指南链接
- 修复建议
- 合规性映射

### 自定义策略

添加自定义 Checkov 策略：

```python
# custom_policy.py
from checkov.common.models.enums import CheckResult

class CustomCheck(BaseResourceCheck):
    def scan_resource_conf(self, conf):
        # 您的自定义逻辑
        return CheckResult.PASSED
```

## GitLeaks

### 关于

- **版本**：8.18.4
- **开发者**：Zachary Rice
- **许可证**：MIT
- **网站**：https://github.com/gitleaks/gitleaks

### 功能

**检测方法**：
- 正则表达式模式
- 熵分析
- Shannon 熵
- 文件路径扫描

**支持的密钥**：
- API 密钥（1000+ 服务）
- 私钥
- 令牌和密码
- 连接字符串
- 云凭证

**功能**：
- 低误报率
- 快速扫描
- 自定义规则支持
- JSON/SARIF 输出

### 集成

GitLeaks 增强密钥检测：

```javascript
// 我们的内置扫描工具检测模式
const apiKey = "AIzaSyC123...";

// GitLeaks 添加：
// - 熵分数（4.2）
// - 规则 ID（google-api-key）
// - 置信度级别（高）
```

### 自定义规则

添加自定义 GitLeaks 规则：

```toml
# .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''custom_[0-9a-zA-Z]{32}'''
tags = ["api", "custom"]
```

## 性能比较

| 工具 | 速度 | 准确性 | 覆盖面 |
|------|------|--------|--------|
| 内置扫描工具 | ⚡⚡⚡ 非常快 | ⭐⭐⭐ 好 | ⭐⭐ 中等 |
| GitLeaks | ⚡⚡ 快 | ⭐⭐⭐⭐ 优秀 | ⭐⭐⭐ 广泛 |
| Trivy | ⚡⚡ 快 | ⭐⭐⭐⭐ 优秀 | ⭐⭐⭐⭐ 综合 |
| Checkov | ⚡ 中等 | ⭐⭐⭐⭐ 优秀 | ⭐⭐⭐⭐ 综合 |

## 最佳实践

### 何时使用外部工具

✅ **对以下情况使用沙箱 + 外部工具**：
- 生产代码审查
- 部署前扫描
- 合规性要求
- 未知/不受信任的代码

⚡ **对以下情况使用内置扫描工具**：
- 快速开发检查
- IDE 集成
- 立即反馈
- 离线扫描

### 优化提示

1. **缓存 Docker 镜像**：拉取一次，多次使用
2. **并行扫描**：同时运行工具
3. **过滤结果**：专注于高/严重严重程度
4. **定期更新**：每月添加新规则和 CVE

### 安全考虑

所有外部工具在隔离的 Docker 容器中运行，具有：
- ✅ 只读文件系统
- ✅ 无网络访问
- ✅ 有限的 CPU/内存
- ✅ 无新特权
- ✅ 已删除的能力

## 更新

### 检查版本

```bash
docker run security-scanner-mcp sh -c "
  trivy --version
  gitleaks version
  checkov --version
"
```

### 更新工具

```bash
# 拉取包含更新工具的最新镜像
docker pull ongjin/security-scanner-mcp:latest
```

## 工具输出示例

### Trivy 输出

```json
{
  "Type": "dockerfile",
  "ID": "CIS-DI-0001",
  "Title": "Create a user for the container",
  "Severity": "HIGH",
  "Resolution": "Add USER instruction"
}
```

### Checkov 输出

```json
{
  "check_id": "CKV_AWS_18",
  "check_name": "Ensure S3 bucket has server-side encryption",
  "severity": "HIGH",
  "guideline": "https://..."
}
```

### GitLeaks 输出

```json
{
  "Description": "Google API Key",
  "RuleID": "google-api-key",
  "Entropy": 4.2,
  "Match": "AIza...abc",
  "Secret": "AIzaSyC1234567890abcdef"
}
```

## 下一步

- [报告](./reporting.md) - 生成综合报告
- [集成](./integration.md) - CI/CD 集成
- [沙箱](../features/sandbox.md) - 了解 Docker 隔离
