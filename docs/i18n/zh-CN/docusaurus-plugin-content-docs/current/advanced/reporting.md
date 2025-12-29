---
sidebar_position: 2
---

# 安全报告

生成包含图表和业界标准格式的综合安全报告。

## 报告类型

### Markdown 报告

人工可读的文本格式，包含：
- 执行摘要
- 严重程度细分
- 详细发现
- 修复指导

### Mermaid 图表

可视化表示：
- **饼图**：严重程度分布
- **柱状图**：漏洞类别
- **流程图**：攻击场景

### SARIF 格式

静态分析结果交换格式：
- GitHub Code Scanning 兼容
- VS Code 集成
- CI/CD 工具支持

## generate-security-report 工具

### 用法

```
我：生成综合安全报告

[您的代码或扫描结果]
```

### 示例输出

```markdown
# 🛡️ 安全扫描仪表板

## 📊 整体摘要

**总漏洞数**：8

| 严重程度 | 数量 | 百分比 |
|---------|------|--------|
| 🔴 严重 | 2 | 25% |
| 🟠 高 | 3 | 37.5% |
| 🟡 中 | 2 | 25% |
| 🟢 低 | 1 | 12.5% |

## 🎯 严重程度分布

\```mermaid
pie title Vulnerability Distribution by Severity
    "🔴 Critical" : 2
    "🟠 High" : 3
    "🟡 Medium" : 2
    "🟢 Low" : 1
\```

## 📋 SARIF 报告

与 GitHub Code Scanning、VS Code 和其他工具兼容的 SARIF JSON。

\```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0",
  "runs": [...]
}
\```
```

## CVE/OWASP 集成

报告包括：

### CVE 信息
- CVE ID
- CVSS 分数
- 受影响的版本
- 修复版本
- 参考资料

### OWASP Top 10 映射
- A01:2021 - 破损访问控制
- A02:2021 - 密码学故障
- A03:2021 - 注入
- A04:2021 - 不安全的设计
- A05:2021 - 安全配置错误
- A06:2021 - 易受攻击的过时组件
- A07:2021 - 识别和身份验证故障
- A08:2021 - 软件和数据完整性故障
- A09:2021 - 安全日志和监控故障
- A10:2021 - 服务器端请求伪造

## GitHub 集成

### Code Scanning 提醒

上传 SARIF 到 GitHub：

```bash
# 生成 SARIF
curl -X POST https://api.github.com/repos/OWNER/REPO/code-scanning/sarifs \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d @report.sarif.json
```

### Actions 集成

```yaml
- name: Security Scan
  run: |
    # 生成 SARIF 报告
    # 上传到 GitHub

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-report.sarif
```

## 报告自定义

### 按严重程度过滤

```
我：生成仅显示严重和高严重程度问题的报告
```

### 专注于类别

```
我：创建专注于注入漏洞的报告
```

### 包含修复

```
我：生成包含详细修复说明的报告
```

## 导出格式

### JSON

```json
{
  "timestamp": "2024-01-20T10:30:00Z",
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  },
  "issues": [...]
}
```

### CSV

```csv
Type,Severity,File,Line,Message,Fix
"SQL Injection","high","api.js",45,"Template literal SQL","Use prepared statements"
```

### HTML

交互式 HTML 报告，包含：
- 可排序的表格
- 可过滤的结果
- 可点击的参考资料
- 响应式设计

## 最佳实践

1. **定期生成**：每次主要代码更改后
2. **跟踪趋势**：比较一段时间内的报告
3. **与团队分享**：包含在代码审查中
4. **CI/CD 集成**：自动化报告生成
5. **记录修复**：随问题解决更新报告

## 报告模板

### 执行摘要模板

```markdown
# 安全评估报告

**项目**：[名称]
**日期**：[日期]
**扫描工具**：Security Scanner MCP

## 执行摘要

此评估在 [Y] 个文件中发现了 [X] 个安全漏洞。
需要立即采取行动来处理 [Z] 个严重问题。

## 主要发现

1. [发现 1]
2. [发现 2]
3. [发现 3]

## 建议

1. [建议 1]
2. [建议 2]
```

### 技术报告模板

```markdown
# 技术安全分析

## 方法
- 静态分析
- 模式匹配
- 外部工具集成（Trivy、Checkov、GitLeaks）

## 范围
- [扫描的文件]
- [分析的语言]
- [应用的规则集]

## 详细发现
[技术详情...]
```

## 下一步

- [集成](./integration.md) - CI/CD 集成
- [外部工具](./external-tools.md) - 增强扫描
- [配置](../reference/configuration.md) - 报告自定义
