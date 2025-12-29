---
sidebar_position: 3
---

# API 参考

Security Scanner MCP 的编程 API。

## 安装

```bash
npm install security-scanner-mcp
```

## 核心扫描工具

### scanSecrets

检测代码中硬编码的密钥。

```typescript
import { scanSecrets } from 'security-scanner-mcp';

const code = `
  const apiKey = "AIzaSyC1234567890";
  const password = "admin123";
`;

const issues = scanSecrets(code);

console.log(issues);
// [
//   {
//     type: 'Google API Key',
//     severity: 'critical',
//     message: 'Google API Key is hardcoded',
//     fix: 'Use environment variables',
//     line: 2,
//     match: 'AIza****890',
//     owaspCategory: 'A07:2021',
//     cweId: 'CWE-798'
//   }
// ]
```

**参数**：
- `code: string` - 要扫描的源代码
- 返回：`SecurityIssue[]`

### scanInjection

查找 SQL、NoSQL 和命令注入漏洞。

```typescript
import { scanInjection } from 'security-scanner-mcp';

const code = `
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  exec(\`ping \${host}\`);
`;

const issues = scanInjection(code, 'javascript');

console.log(issues);
// [
//   {
//     type: 'Template Literal SQL',
//     severity: 'high',
//     message: 'SQL query uses template literals',
//     fix: 'Use prepared statements',
//     line: 2
//   },
//   {
//     type: 'Command Injection',
//     severity: 'critical',
//     message: 'exec() called with user input',
//     fix: 'Use execFile with argument array',
//     line: 3
//   }
// ]
```

**参数**：
- `code: string` - 源代码
- `language: string` - 'javascript' | 'typescript' | 'python' | 'java' | 'go'
- 返回：`SecurityIssue[]`

### scanXss

识别跨站脚本漏洞。

```typescript
import { scanXss } from 'security-scanner-mcp';

const code = `
  element.innerHTML = userInput;
  eval(code);
`;

const issues = scanXss(code, 'javascript');
```

**参数**：
- `code: string`
- `language: string`
- 返回：`SecurityIssue[]`

### scanCrypto

检查密码学弱点。

```typescript
import { scanCrypto } from 'security-scanner-mcp';

const code = `
  const hash = crypto.createHash('md5');
  const random = Math.random();
`;

const issues = scanCrypto(code, 'javascript');
```

**参数**：
- `code: string`
- `language: string`
- 返回：`SecurityIssue[]`

### scanAuth

审计身份验证和会话安全。

```typescript
import { scanAuth } from 'security-scanner-mcp';

const code = `
  res.cookie('session', token);
  app.use(cors({ origin: '*' }));
`;

const issues = scanAuth(code, 'javascript');
```

**参数**：
- `code: string`
- `language: string`
- 返回：`SecurityIssue[]`

### scanPath

查找路径穿越和文件漏洞。

```typescript
import { scanPath } from 'security-scanner-mcp';

const code = `
  const file = fs.readFileSync(userPath);
  fs.rmSync(userDir, { recursive: true });
`;

const issues = scanPath(code, 'javascript');
```

**参数**：
- `code: string`
- `language: string`
- 返回：`SecurityIssue[]`

## 综合扫描

### scanAll

一次运行所有扫描工具。

```typescript
import { scanAll } from 'security-scanner-mcp';

const code = `/* your code */`;
const language = 'javascript';

const allIssues = scanAll(code, language);

console.log(allIssues.summary);
// {
//   total: 10,
//   critical: 2,
//   high: 3,
//   medium: 4,
//   low: 1
// }
```

**参数**：
- `code: string`
- `language: string`
- 返回：`ScanResult`

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
  duration?: number;
  linesScanned?: number;
}
```

## IaC 扫描

### scanDockerfile

```typescript
import { scanDockerfile } from 'security-scanner-mcp/iac';

const dockerfile = `
FROM node:latest
ENV SECRET="abc123"
RUN apt-get update
`;

const issues = scanDockerfile(dockerfile);
```

### scanKubernetes

```typescript
import { scanKubernetes } from 'security-scanner-mcp/iac';

const yaml = `
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
`;

const issues = scanKubernetes(yaml);
```

### scanTerraform

```typescript
import { scanTerraform } from 'security-scanner-mcp/iac';

const tf = `
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`;

const issues = scanTerraform(tf);
```

## 外部工具

### 沙箱执行

```typescript
import { scanInSandbox } from 'security-scanner-mcp/sandbox';

const result = await scanInSandbox(code, {
  language: 'javascript',
  timeout: 30000,
  memory: '512m',
  cpu: 0.5,
  tools: ['trivy', 'checkov', 'gitleaks']
});

console.log(result);
// {
//   success: true,
//   issues: [...],
//   summary: {...},
//   metadata: {
//     tools: ['builtin', 'gitleaks', 'trivy'],
//     duration: 1234
//   }
// }
```

## 报告

### 生成报告

```typescript
import { generateReport } from 'security-scanner-mcp/reporting';

const report = generateReport(issues, {
  format: 'markdown',  // 'markdown' | 'html' | 'sarif'
  includeDiagrams: true,
  includeSARIF: true,
  template: 'default'
});

console.log(report);
```

### SARIF 导出

```typescript
import { toSARIF } from 'security-scanner-mcp/reporting';

const sarif = toSARIF(issues, {
  toolName: 'Security Scanner MCP',
  toolVersion: '1.0.0'
});

// 与 GitHub Code Scanning 兼容
fs.writeFileSync('security.sarif', JSON.stringify(sarif, null, 2));
```

## 类型定义

### SecurityIssue

```typescript
interface SecurityIssue {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  fix: string;
  line?: number;
  match?: string;
  owaspCategory?: string;
  cweId?: string;
  metadata?: Record<string, any>;
}
```

### ScanOptions

```typescript
interface ScanOptions {
  language?: string;
  filename?: string;
  excludePatterns?: string[];
  severity?: {
    minLevel?: 'critical' | 'high' | 'medium' | 'low';
  };
  rules?: {
    secrets?: boolean;
    injection?: boolean;
    xss?: boolean;
    crypto?: boolean;
    auth?: boolean;
    path?: boolean;
  };
}
```

## 错误处理

```typescript
import { scanAll, ScannerError } from 'security-scanner-mcp';

try {
  const result = scanAll(code, 'javascript');
} catch (error) {
  if (error instanceof ScannerError) {
    console.error('Scanner error:', error.code, error.message);
  }
}
```

## 异步 API

### scanAllAsync

用于大型代码库：

```typescript
import { scanAllAsync } from 'security-scanner-mcp';

const result = await scanAllAsync(code, language, {
  timeout: 60000,
  parallel: true
});
```

## CLI 集成

### 编程 CLI

```typescript
import { runCLI } from 'security-scanner-mcp/cli';

await runCLI(['scan', 'src/', '--format', 'json']);
```

## 事件

### 扫描工具事件

```typescript
import { Scanner } from 'security-scanner-mcp';

const scanner = new Scanner();

scanner.on('progress', (progress) => {
  console.log(`Scanning: ${progress.current}/${progress.total}`);
});

scanner.on('issue', (issue) => {
  console.log(`Found: ${issue.type} at line ${issue.line}`);
});

await scanner.scan(code, 'javascript');
```

## 下一步

- [配置](./configuration.md) - 高级配置
- [漏洞](./vulnerabilities.md) - 详细的漏洞参考
- [集成](../advanced/integration.md) - CI/CD 集成
