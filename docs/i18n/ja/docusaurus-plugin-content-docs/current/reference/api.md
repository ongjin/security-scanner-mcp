---
sidebar_position: 3
---

# APIリファレンス

Security Scanner MCPのプログラム的なAPI。

## インストール

```bash
npm install security-scanner-mcp
```

## コアスキャナー

### scanSecrets

コード内のハードコードされたシークレットを検出します。

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
//     message: 'Google APIキーがハードコード',
//     fix: '環境変数を使用',
//     line: 2,
//     match: 'AIza****890',
//     owaspCategory: 'A07:2021',
//     cweId: 'CWE-798'
//   }
// ]
```

**パラメータ**:
- `code: string` - スキャンするソースコード
- 戻り値: `SecurityIssue[]`

### scanInjection

SQL、NoSQL、コマンドインジェクション脆弱性を検出します。

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
//     message: 'SQLクエリがテンプレートリテラルを使用',
//     fix: 'プリペアドステートメントを使用',
//     line: 2
//   },
//   {
//     type: 'Command Injection',
//     severity: 'critical',
//     message: 'exec()がユーザー入力で呼び出し',
//     fix: '引数配列でexecFileを使用',
//     line: 3
//   }
// ]
```

**パラメータ**:
- `code: string` - ソースコード
- `language: string` - 'javascript' | 'typescript' | 'python' | 'java' | 'go'
- 戻り値: `SecurityIssue[]`

### scanXss

Cross-Site Scripting脆弱性を特定します。

```typescript
import { scanXss } from 'security-scanner-mcp';

const code = `
  element.innerHTML = userInput;
  eval(code);
`;

const issues = scanXss(code, 'javascript');
```

**パラメータ**:
- `code: string`
- `language: string`
- 戻り値: `SecurityIssue[]`

### scanCrypto

暗号化の脆弱性をチェックします。

```typescript
import { scanCrypto } from 'security-scanner-mcp';

const code = `
  const hash = crypto.createHash('md5');
  const random = Math.random();
`;

const issues = scanCrypto(code, 'javascript');
```

**パラメータ**:
- `code: string`
- `language: string`
- 戻り値: `SecurityIssue[]`

### scanAuth

認証とセッションセキュリティを監査します。

```typescript
import { scanAuth } from 'security-scanner-mcp';

const code = `
  res.cookie('session', token);
  app.use(cors({ origin: '*' }));
`;

const issues = scanAuth(code, 'javascript');
```

**パラメータ**:
- `code: string`
- `language: string`
- 戻り値: `SecurityIssue[]`

### scanPath

パストラバーサルとファイルの脆弱性を検出します。

```typescript
import { scanPath } from 'security-scanner-mcp';

const code = `
  const file = fs.readFileSync(userPath);
  fs.rmSync(userDir, { recursive: true });
`;

const issues = scanPath(code, 'javascript');
```

**パラメータ**:
- `code: string`
- `language: string`
- 戻り値: `SecurityIssue[]`

## 包括的なスキャン

### scanAll

すべてのスキャナーを一度に実行します。

```typescript
import { scanAll } from 'security-scanner-mcp';

const code = `/* コード */`;
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

**パラメータ**:
- `code: string`
- `language: string`
- 戻り値: `ScanResult`

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

## IaCスキャン

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

## 外部ツール

### サンドボックス実行

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

## レポート

### レポートを生成

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

### SARIF エクスポート

```typescript
import { toSARIF } from 'security-scanner-mcp/reporting';

const sarif = toSARIF(issues, {
  toolName: 'Security Scanner MCP',
  toolVersion: '1.0.0'
});

// GitHub Code Scanningと互換
fs.writeFileSync('security.sarif', JSON.stringify(sarif, null, 2));
```

## 型定義

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

## エラーハンドリング

```typescript
import { scanAll, ScannerError } from 'security-scanner-mcp';

try {
  const result = scanAll(code, 'javascript');
} catch (error) {
  if (error instanceof ScannerError) {
    console.error('スキャナーエラー:', error.code, error.message);
  }
}
```

## 非同期API

### scanAllAsync

大規模なコードベースの場合:

```typescript
import { scanAllAsync } from 'security-scanner-mcp';

const result = await scanAllAsync(code, language, {
  timeout: 60000,
  parallel: true
});
```

## CLI統合

### プログラム的なCLI

```typescript
import { runCLI } from 'security-scanner-mcp/cli';

await runCLI(['scan', 'src/', '--format', 'json']);
```

## イベント

### スキャナーイベント

```typescript
import { Scanner } from 'security-scanner-mcp';

const scanner = new Scanner();

scanner.on('progress', (progress) => {
  console.log(`スキャン: ${progress.current}/${progress.total}`);
});

scanner.on('issue', (issue) => {
  console.log(`検出: ${issue.type} at line ${issue.line}`);
});

await scanner.scan(code, 'javascript');
```

## 次のステップ

- [設定](./configuration.md) - 高度な設定
- [脆弱性](./vulnerabilities.md) - 詳細な脆弱性リファレンス
- [統合](../advanced/integration.md) - CI/CD統合
