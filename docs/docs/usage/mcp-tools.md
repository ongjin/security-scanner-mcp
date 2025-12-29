---
sidebar_position: 3
---

# MCP Tools Reference

Complete reference for all Security Scanner MCP tools.

## Core Scanning Tools

### scan-security

**Description**: Comprehensive security scan - runs all checks at once

**Usage**: Best for general purpose scanning

```
Me: Scan this code for security issues
```

**What it does**:
- Runs all 7 scanners simultaneously
- Combines results
- Returns comprehensive report

### scan-secrets

**Description**: Detect hardcoded secrets

**Detects**:
- API keys (AWS, Google, GitHub, Stripe, etc.)
- Passwords and tokens
- Database connection strings
- Private keys
- OAuth secrets

**Usage**:
```
Me: Check for hardcoded secrets in this code
```

### scan-injection

**Description**: Find SQL/NoSQL/Command injection vulnerabilities

**Detects**:
- SQL injection (string concatenation, template literals)
- NoSQL injection (MongoDB)
- Command injection (exec, spawn, system)
- LDAP injection

**Usage**:
```
Me: Scan for injection vulnerabilities
```

### scan-xss

**Description**: Identify Cross-Site Scripting risks

**Detects**:
- `dangerouslySetInnerHTML` (React)
- `innerHTML` / `outerHTML`
- jQuery `.html()`
- Vue `v-html`
- `eval()` / `new Function()`

**Usage**:
```
Me: Check for XSS vulnerabilities
```

### scan-crypto

**Description**: Check cryptographic weaknesses

**Detects**:
- Weak hashing (MD5, SHA1)
- Insecure random (`Math.random`)
- Hardcoded keys/IVs
- SSL validation disabled
- Vulnerable TLS versions

**Usage**:
```
Me: Analyze cryptographic security
```

### scan-auth

**Description**: Audit authentication and session security

**Detects**:
- JWT misconfigurations
- Insecure cookies
- CORS wildcards
- Weak password policies
- Session fixation risks

**Usage**:
```
Me: Review authentication security
```

### scan-path

**Description**: Find file and path vulnerabilities

**Detects**:
- Path traversal
- Dangerous file operations
- Insecure file uploads
- Zip Slip (Java)
- Pickle deserialization (Python)

**Usage**:
```
Me: Check for path traversal issues
```

### scan-dependencies

**Description**: Check for vulnerable dependencies

**Checks**:
- package.json (npm audit)
- requirements.txt (Python)
- go.mod (Go)

**Usage**:
```
Me: Scan dependencies for vulnerabilities
```

## Infrastructure Tools

### scan-iac

**Description**: Scan Infrastructure as Code files

**Supports**:
- Dockerfile (CIS Docker Benchmark)
- Kubernetes YAML (Pod Security Standards)
- Terraform HCL (Multi-cloud)

**Usage**:
```
Me: Scan this Dockerfile
```

## Advanced Tools

### get-fix-suggestion

**Description**: Get auto-generated fix code

**Returns**:
- Before/After code comparison
- Explanation
- Alternative solutions

**Usage**:
```
Me: How do I fix this SQL injection?
```

**Parameters**:
- `issue`: Description of the vulnerability
- `code`: Original vulnerable code
- `language`: Programming language

### generate-security-report

**Description**: Create comprehensive security reports

**Generates**:
- Mermaid diagrams (pie, bar, flowchart)
- SARIF format (GitHub Code Scanning compatible)
- CVE/OWASP information
- Attack scenario analysis

**Usage**:
```
Me: Generate a full security report with diagrams
```

**Output includes**:
- Overall summary
- Severity distribution chart
- Vulnerability categories chart
- Attack scenario flowchart
- SARIF JSON for CI/CD integration

### scan-in-sandbox

**Description**: Run scans in Docker isolated environment

**Features**:
- Memory/CPU limits
- Network isolation
- External tools (Trivy, Checkov, GitLeaks)

**Usage**:
```
Me: Scan this code in a sandbox
```

**Security settings**:
- Memory: 128MB - 2GB
- CPU: 0.1 - 2.0 cores
- Timeout: 5s - 5min
- Network: Disabled
- Privileges: Minimal

## Tool Parameters

### Common Parameters

All scanning tools accept:
- `code`: Source code to scan (string)
- `language`: Programming language (optional, auto-detected)
- `filename`: Original filename (optional)

### Language Detection

Auto-detected languages:
- JavaScript
- TypeScript
- Python
- Java
- Go

## Tool Response Format

### Standard Issue Format

```typescript
interface SecurityIssue {
  type: string;          // Vulnerability type
  severity: string;      // critical | high | medium | low
  message: string;       // Human-readable description
  fix: string;          // Remediation suggestion
  line?: number;        // Line number (1-indexed)
  match?: string;       // Matched text (masked for secrets)
  owaspCategory?: string;  // OWASP Top 10 mapping
  cweId?: string;       // CWE identifier
  metadata?: object;    // Tool-specific data
}
```

### Scan Result Format

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

## Error Handling

Tools return errors in standard format:

```json
{
  "success": false,
  "error": "Error description",
  "code": "ERROR_CODE"
}
```

Common error codes:
- `INVALID_INPUT`: Invalid code or parameters
- `LANGUAGE_NOT_SUPPORTED`: Unsupported language
- `SCAN_TIMEOUT`: Scan exceeded time limit
- `DOCKER_NOT_AVAILABLE`: Docker not installed (sandbox only)

## Best Practices

1. **Use scan-security first**: Get comprehensive overview
2. **Target specific scanners**: Use individual tools for deep analysis
3. **Request fixes**: Follow up scans with get-fix-suggestion
4. **Generate reports**: Use for documentation and CI/CD
5. **Sandbox untrusted code**: Use scan-in-sandbox for unknown sources

## Next Steps

- [Basic Usage](./basic-usage.md) - Learn general usage patterns
- [Advanced Features](../advanced/external-tools.md) - External tool integration
- [API Reference](../reference/api.md) - Programmatic API
