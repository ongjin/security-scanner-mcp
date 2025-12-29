---
sidebar_position: 4
---

# Docker 沙箱扫描

在隔离的 Docker 环境中运行安全扫描以最大化安全性。

## 为什么使用沙箱?

保护您的主机系统免受潜在恶意代码的侵害：
- ✅ **隔离执行** - 代码在容器化环境中运行
- ✅ **资源限制** - CPU、内存和时间限制
- ✅ **网络隔离** - 无外部网络访问
- ✅ **只读文件系统** - 无法修改主机文件
- ✅ **增强扫描** - 使用外部工具（Trivy、Checkov、GitLeaks）

## 设置

### 从 Docker Hub 拉取（推荐）

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### 或从源代码构建

```bash
npm run docker:build
```

**注意**：构建需要 5-10 分钟并创建约 500MB 的镜像，包含：
- Trivy v0.50.4
- GitLeaks v8.18.4
- Checkov（基于 Python）

## 用法

### 基本沙箱扫描

```
我：在沙箱中扫描此代码

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claude 将调用 `scan-in-sandbox` 它：
1. 将代码写入临时文件
2. 启动 Docker 容器
3. 在容器内运行所有扫描工具
4. 以 JSON 格式返回结果
5. 清理容器

### 扫描不受信任的代码

```
我：此代码看起来可疑，请安全地扫描它

[粘贴可能的恶意代码]
```

## 安全配置

### 默认设置

```
内存限制：512MB
CPU 限制：0.5 核心
超时：30 秒
网络：禁用
文件系统：只读（除 /tmp）
能力：已删除（no-new-privileges）
```

### 可自定义的选项

您可以通过环境变量调整这些：

```bash
SANDBOX_MEMORY=1g \
SANDBOX_CPU=1.0 \
SANDBOX_TIMEOUT=60000 \
scan-in-sandbox
```

## 沙箱中可用的扫描工具

### 内置扫描工具
- 密钥检测
- SQL/NoSQL/命令注入
- XSS 漏洞
- 密码学问题
- 身份验证问题
- 路径穿越

### 外部工具（Docker 仅）
- **GitLeaks**：增强的密钥检测，包含熵分析
- **Trivy**：IaC 和容器漏洞扫描
- **Checkov**：基础设施即代码安全分析

## Docker 容器详情

### 基础镜像
```dockerfile
FROM node:20-alpine
```

### 安全加固

```dockerfile
# 非 root 用户
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner

# 只读根文件系统
# 没有新特权
# 已删除的能力
# 网络已禁用
```

### 已安装的工具

```bash
# 验证工具已安装
docker run security-scanner-mcp:latest sh -c "
  trivy --version &&
  gitleaks version &&
  checkov --version
"
```

## 结果格式

沙箱扫描返回综合 JSON：

```json
{
  "success": true,
  "language": "javascript",
  "filename": "code.js",
  "issuesCount": 3,
  "issues": [
    {
      "type": "Google API Key",
      "severity": "critical",
      "message": "Google API Key is hardcoded",
      "fix": "Use environment variables",
      "line": 1,
      "metadata": {
        "tool": "gitleaks",
        "ruleId": "google-api-key",
        "entropy": 4.2
      }
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

## 性能考虑

### 容器启动
- **首次运行**：~2-3 秒（冷启动）
- **后续运行**：~1 秒（缓存）

### 扫描持续时间
- **小文件（100 行以下）**：少于 5 秒
- **中等文件（100-500 行）**：5-15 秒
- **大文件（500 行以上）**：15-30 秒

### 资源使用
- **内存**：每次扫描约 100-200MB
- **CPU**：最小（0.1-0.5 核心）
- **磁盘**：临时文件自动清理

## 故障排除

### 找不到容器

```bash
# 检查镜像是否存在
docker images | grep security-scanner-mcp

# 如果缺少则拉取
docker pull ongjin/security-scanner-mcp:latest
```

### 权限被拒绝

```bash
# 将用户添加到 docker 组
sudo usermod -aG docker $USER

# 重启 shell
```

### 超时问题

```bash
# 增加超时时间（毫秒）
SANDBOX_TIMEOUT=60000 scan-in-sandbox
```

## 最佳实践

1. **用于不受信任的代码**：始终扫描来自未知源的代码
2. **定期镜像更新**：每月拉取最新安全更新
3. **监控资源使用**：用限制防止滥用
4. **清理**：容器自动删除，但定期检查
5. **网络隔离**：保持网络禁用，除非需要

## 高级配置

### 自定义 Docker 镜像

```dockerfile
FROM security-scanner-mcp:latest

# 添加自定义扫描工具
RUN pip3 install custom-scanner

# 添加自定义规则
COPY custom-rules.yaml /app/rules/
```

### CI/CD 集成

```yaml
# GitHub Actions 示例
- name: Scan Code in Sandbox
  run: |
    docker pull ongjin/security-scanner-mcp:latest
    docker run --rm \
      -v ${{ github.workspace }}:/code:ro \
      security-scanner-mcp:latest \
      scan /code
```

## 下一步

- [外部工具](../advanced/external-tools.md) - 了解 Trivy、Checkov、GitLeaks
- [报告](../advanced/reporting.md) - 生成 SARIF 报告
- [集成](../advanced/integration.md) - CI/CD 集成
