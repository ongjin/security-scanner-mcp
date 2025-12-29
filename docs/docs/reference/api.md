---
sidebar_position: 3
---

# API Reference

Programmatic API for Security Scanner MCP.

## Installation

```bash
npm install security-scanner-mcp
```

## Core Scanners

### scanSecrets

Detect hardcoded secrets in code.

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

**Parameters**:
- `code: string` - Source code to scan
- Returns: `SecurityIssue[]`

### scanInjection

Find SQL, NoSQL, and command injection vulnerabilities.

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

**Parameters**:
- `code: string` - Source code
- `language: string` - 'javascript' | 'typescript' | 'python' | 'java' | 'go'
- Returns: `SecurityIssue[]`

### scanXss

Identify Cross-Site Scripting vulnerabilities.

```typescript
import { scanXss } from 'security-scanner-mcp';

const code = `
  element.innerHTML = userInput;
  eval(code);
`;

const issues = scanXss(code, 'javascript');
```

**Parameters**:
- `code: string`
- `language: string`
- Returns: `SecurityIssue[]`

### scanCrypto

Check cryptographic weaknesses.

```typescript
import { scanCrypto } from 'security-scanner-mcp';

const code = `
  const hash = crypto.createHash('md5');
  const random = Math.random();
`;

const issues = scanCrypto(code, 'javascript');
```

**Parameters**:
- `code: string`
- `language: string`
- Returns: `SecurityIssue[]`

### scanAuth

Audit authentication and session security.

```typescript
import { scanAuth } from 'security-scanner-mcp';

const code = `
  res.cookie('session', token);
  app.use(cors({ origin: '*' }));
`;

const issues = scanAuth(code, 'javascript');
```

**Parameters**:
- `code: string`
- `language: string`
- Returns: `SecurityIssue[]`

### scanPath

Find path traversal and file vulnerabilities.

```typescript
import { scanPath } from 'security-scanner-mcp';

const code = `
  const file = fs.readFileSync(userPath);
  fs.rmSync(userDir, { recursive: true });
`;

const issues = scanPath(code, 'javascript');
```

**Parameters**:
- `code: string`
- `language: string`
- Returns: `SecurityIssue[]`

## Comprehensive Scanning

### scanAll

Run all scanners at once.

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

**Parameters**:
- `code: string`
- `language: string`
- Returns: `ScanResult`

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

## IaC Scanning

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

## External Tools

### Sandbox Execution

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

## Reporting

### Generate Report

```typescript
import { generateReport } from 'security-scanner-mcp/reporting';

const report = generateReport(issues, {
  format: 'markdown',  // 'markdown' | 'html' | 'sarif'
  includeDiagrams: true,
  includeS ARIF: true,
  template: 'default'
});

console.log(report);
```

### SARIF Export

```typescript
import { toSARIF } from 'security-scanner-mcp/reporting';

const sarif = toSARIF(issues, {
  toolName: 'Security Scanner MCP',
  toolVersion: '1.0.0'
});

// Compatible with GitHub Code Scanning
fs.writeFileSync('security.sarif', JSON.stringify(sarif, null, 2));
```

## Type Definitions

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

## Error Handling

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

## Async API

### scanAllAsync

For large codebases:

```typescript
import { scanAllAsync } from 'security-scanner-mcp';

const result = await scanAllAsync(code, language, {
  timeout: 60000,
  parallel: true
});
```

## CLI Integration

### Programmatic CLI

```typescript
import { runCLI } from 'security-scanner-mcp/cli';

await runCLI(['scan', 'src/', '--format', 'json']);
```

## Events

### Scanner Events

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

## Next Steps

- [Configuration](./configuration.md) - Advanced configuration
- [Vulnerabilities](./vulnerabilities.md) - Detailed vulnerability reference
- [Integration](../advanced/integration.md) - CI/CD integration
