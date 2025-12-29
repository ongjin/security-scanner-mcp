---
sidebar_position: 2
---

# 基础设施即代码（IaC）扫描

扫描您的基础设施配置文件以发现安全配置错误。

## 支持的 IaC 格式

### 🐳 Dockerfile

**基于 CIS Docker 基准的 15+ 规则**

检测的常见问题：
- 以 root 身份运行容器
- ENV 或 ARG 中的硬编码密钥
- 使用 `latest` 标签
- 不必要的端口暴露
- 缺少健康检查
- apt-get update 后未清理
- 使用 ADD 而不是 COPY
- 缺少 USER 指令

**示例：**

```dockerfile
# ❌ 易受攻击
FROM node:latest
ENV API_KEY="secret123"
RUN apt-get update && apt-get install -y curl
EXPOSE 22
# 无 USER 指令 - 以 root 身份运行

# ✅ 安全
FROM node:20-alpine
ARG API_KEY
RUN apk add --no-cache curl && \
    rm -rf /var/cache/apk/*
EXPOSE 3000
USER node
HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1
```

### ☸️ Kubernetes

**基于 Pod 安全标准的 13+ 规则**

检测的常见问题：
- 特权容器
- 以 root 身份运行
- 主机网络/PID/IPC 使用
- 危险的能力添加（SYS_ADMIN、NET_ADMIN）
- 缺少资源限制
- 可读写的根文件系统
- 允许特权提升
- 主机路径挂载

**示例：**

```yaml
# ❌ 易受攻击
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
    resources: {}

# ✅ 安全
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
```

### 🏗️ Terraform

**AWS/GCP/Azure 的 15+ 规则**

检测的常见问题：
- 公开 IP 分配给敏感资源
- 禁用存储/数据库加密
- 安全组向 0.0.0.0/0 开放
- 可公开访问的 S3 存储桶
- 缺少 VPC 流日志
- 未加密的 EBS 卷
- 包含通配符的 IAM 策略
- 缺少敏感操作的 MFA

**示例：**

```hcl
# ❌ 易受攻击
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ 安全
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # 仅内部
  }
}
```

## 用法

### 基本 IaC 扫描

```
我：扫描我的 Dockerfile 以查找安全问题

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update && apt-get install curl
```

### 扫描 Kubernetes YAML

```
我：检查此 Kubernetes 清单是否存在安全问题

[粘贴 YAML]
```

### 扫描 Terraform 配置

```
我：审查此 Terraform 文件以查找安全配置错误

[粘贴 .tf 文件]
```

## 外部工具集成

在使用 Docker 沙箱（`scan-in-sandbox`）时，使用额外的业界标准工具：

### Trivy
- **版本**：0.50.4
- **用途**：容器和 IaC 漏洞扫描工具
- 综合的配置错误检测
- CVE 数据库集成

### Checkov
- **用途**：IaC 安全扫描工具
- 1000+ 内置策略
- 合规框架（CIS、PCI-DSS、HIPAA）
- 多云支持

## 扫描结果

结果包括：
- **规则 ID**：特定的配置错误标识符
- **严重程度**：严重、高、中、低
- **描述**：问题是什么
- **修复**：如何修复
- **OWASP 类别**：映射到 OWASP Top 10
- **CWE ID**：通用弱点枚举

## 最佳实践

1. **提早扫描**：包含在 CI/CD 流程中
2. **使用特定版本**：避免 `latest` 标签
3. **遵循最小权限**：最小权限
4. **启用加密**：静态和传输中的数据
5. **定期更新**：保持基础镜像和依赖项的最新状态

## 下一步

- [自动修复](./auto-fix.md) - 获取自动补救建议
- [沙箱扫描](./sandbox.md) - 在 Docker 隔离环境中运行
- [外部工具](../advanced/external-tools.md) - 了解 Trivy 和 Checkov
