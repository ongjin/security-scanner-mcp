---
sidebar_position: 3
---

# MCP 工具参考

Security Scanner MCP 所有工具的完整参考。

## 核心扫描工具

### scan-security

**描述**：综合安全扫描 - 一次运行所有检查

**用法**：最适合通用扫描

```
我：扫描此代码以查找安全问题
```

**做什么**：
- 同时运行所有 7 个扫描工具
- 合并结果
- 返回综合报告

### scan-secrets

**描述**：检测硬编码密钥

**检测**：
- API 密钥（AWS、Google、GitHub、Stripe 等）
- 密码和令牌
- 数据库连接字符串
- 私钥
- OAuth 秘密

**用法**：
```
我：检查此代码中的硬编码密钥
```

### scan-injection

**描述**：查找 SQL/NoSQL/命令注入漏洞

**检测**：
- SQL 注入（字符串拼接、模板文字）
- NoSQL 注入（MongoDB）
- 命令注入（exec、spawn、system）
- LDAP 注入

**用法**：
```
我：扫描注入漏洞
```

### scan-xss

**描述**：识别跨站脚本风险

**检测**：
- `dangerouslySetInnerHTML`（React）
- `innerHTML` / `outerHTML`
- jQuery `.html()`
- Vue `v-html`
- `eval()` / `new Function()`

**用法**：
```
我：检查 XSS 漏洞
```

### scan-crypto

**描述**：检查密码学弱点

**检测**：
- 弱哈希（MD5、SHA1）
- 不安全的随机数（`Math.random`）
- 硬编码的密钥/IV
- SSL 验证禁用
- 易受攻击的 TLS 版本

**用法**：
```
我：分析密码学安全
```

### scan-auth

**描述**：审计身份验证和会话安全

**检测**：
- JWT 配置错误
- 不安全的 Cookie
- CORS 通配符
- 弱密码策略
- 会话固定风险

**用法**：
```
我：审查身份验证安全
```

### scan-path

**描述**：查找文件和路径漏洞

**检测**：
- 路径穿越
- 危险的文件操作
- 不安全的文件上传
- Zip Slip（Java）
- Pickle 反序列化（Python）

**用法**：
```
我：检查路径穿越问题
```

### scan-dependencies

**描述**：检查易受攻击的依赖项

**检查**：
- package.json（npm audit）
- requirements.txt（Python）
- go.mod（Go）

**用法**：
```
我：扫描依赖项中的漏洞
```

## 基础设施工具

### scan-iac

**描述**：扫描基础设施即代码文件

**支持**：
- Dockerfile（CIS Docker 基准）
- Kubernetes YAML（Pod 安全标准）
- Terraform HCL（多云）

**用法**：
```
我：扫描此 Dockerfile
```

## 高级工具

### get-fix-suggestion

**描述**：获取自动生成的修复代码

**返回**：
- 代码对比（修改前/修改后）
- 解释
- 替代方案

**用法**：
```
我：如何修复这个 SQL 注入？
```

**参数**：
- `issue`：漏洞描述
- `code`：原始易受攻击的代码
- `language`：编程语言

### generate-security-report

**描述**：创建综合安全报告

**生成**：
- Mermaid 图表（饼图、柱状图、流程图）
- SARIF 格式（GitHub Code Scanning 兼容）
- CVE/OWASP 信息
- 攻击场景分析

**用法**：
```
我：生成包含图表的完整安全报告
```

**输出包括**：
- 整体摘要
- 严重程度分布图表
- 漏洞类别图表
- 攻击场景流程图
- 用于 CI/CD 集成的 SARIF JSON

### scan-in-sandbox

**描述**：在 Docker 隔离环境中运行扫描

**功能**：
- 内存/CPU 限制
- 网络隔离
- 外部工具（Trivy、Checkov、GitLeaks）

**用法**：
```
我：在沙箱中扫描此代码
```

**安全设置**：
- 内存：128MB - 2GB
- CPU：0.1 - 2.0 核心
- 超时：5 秒 - 5 分钟
- 网络：已禁用
- 特权：最小

## 工具参数

### 常见参数

所有扫描工具接受：
- `code`：要扫描的源代码（字符串）
- `language`：编程语言（可选，自动检测）
- `filename`：原始文件名（可选）

### 语言检测

自动检测的语言：
- JavaScript
- TypeScript
- Python
- Java
- Go

## 工具响应格式

### 标准问题格式

```typescript
interface SecurityIssue {
  type: string;          // 漏洞类型
  severity: string;      // critical | high | medium | low
  message: string;       // 人工可读的描述
  fix: string;          // 修复建议
  line?: number;        // 行号（1 索引）
  match?: string;       // 匹配文本（密钥已掩盖）
  owaspCategory?: string;  // OWASP Top 10 映射
  cweId?: string;       // CWE 标识符
  metadata?: object;    // 工具特定数据
}
```

### 扫描结果格式

```typescript
interface ScanResult {
  success: boolean;
  issues: SecurityIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}
```

## 错误处理

工具以标准格式返回错误：

```json
{
  "success": false,
  "error": "错误描述",
  "code": "ERROR_CODE"
}
```

常见错误代码：
- `INVALID_INPUT`：无效的代码或参数
- `LANGUAGE_NOT_SUPPORTED`：不支持的语言
- `SCAN_TIMEOUT`：扫描超过时间限制
- `DOCKER_NOT_AVAILABLE`：未安装 Docker（仅沙箱）

## 最佳实践

1. **先使用 scan-security**：获得全面概览
2. **针对特定扫描工具**：使用单个工具进行深度分析
3. **请求修复**：扫描后跟随 get-fix-suggestion
4. **生成报告**：用于文档和 CI/CD
5. **沙箱不受信任的代码**：对未知源使用 scan-in-sandbox

## 下一步

- [基本用法](./basic-usage.md) - 了解通用使用模式
- [高级功能](../advanced/external-tools.md) - 外部工具集成
- [API 参考](../reference/api.md) - 编程 API
