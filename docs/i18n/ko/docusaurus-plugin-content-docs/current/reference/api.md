---
sidebar_position: 3
---

# API 참조

Security Scanner MCP의 프로그래밍 방식 API.

## 설치

```bash
npm install security-scanner-mcp
```

## 핵심 스캐너

### scanSecrets

코드에서 하드코딩된 비밀 정보를 탐지합니다.

```typescript
import { scanSecrets } from 'security-scanner-mcp';

const code = `const apiKey = "AIzaSyC1234567890";`;
const issues = scanSecrets(code);
```

### scanInjection

SQL, NoSQL, 커맨드 인젝션 취약점을 찾습니다.

```typescript
import { scanInjection } from 'security-scanner-mcp';

const code = `const query = \`SELECT * FROM users WHERE id = \${userId}\``;
const issues = scanInjection(code, 'javascript');
```

### scanXss

크로스 사이트 스크립팅 취약점을 식별합니다.

```typescript
import { scanXss } from 'security-scanner-mcp';

const code = `element.innerHTML = userInput;`;
const issues = scanXss(code, 'javascript');
```

## 종합 스캔

### scanAll

모든 스캐너를 한 번에 실행합니다.

```typescript
import { scanAll } from 'security-scanner-mcp';

const code = `/* 코드 */`;
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

## IaC 스캔

### scanDockerfile

```typescript
import { scanDockerfile } from 'security-scanner-mcp/iac';

const dockerfile = `FROM node:latest
ENV SECRET="abc123"`;

const issues = scanDockerfile(dockerfile);
```

## 샌드박스 실행

```typescript
import { scanInSandbox } from 'security-scanner-mcp/sandbox';

const result = await scanInSandbox(code, {
  language: 'javascript',
  timeout: 30000,
  memory: '512m',
  tools: ['trivy', 'gitleaks']
});
```

## 리포트

### generateReport

```typescript
import { generateReport } from 'security-scanner-mcp/reporting';

const report = generateReport(issues, {
  format: 'markdown',
  includeDiagrams: true
});
```

### SARIF 내보내기

```typescript
import { toSARIF } from 'security-scanner-mcp/reporting';

const sarif = toSARIF(issues, {
  toolName: 'Security Scanner MCP',
  toolVersion: '1.0.0'
});
```

## 타입 정의

```typescript
interface SecurityIssue {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  fix: string;
  line?: number;
  owaspCategory?: string;
  cweId?: string;
}
```

## 다음 단계

- [설정](./configuration.md) - 고급 설정
- [취약점](./vulnerabilities.md) - 상세 취약점 참조
