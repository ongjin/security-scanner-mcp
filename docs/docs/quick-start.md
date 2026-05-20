---
sidebar_position: 3
---

# Quick Start

Get started with Security Scanner MCP in 5 minutes!

## Step 1: Basic Code Scan

Ask Claude to scan your code:

```
Me: Scan this code for security issues

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

function findUser(input) {
  db.query(`SELECT * FROM users WHERE id = ${input}`);
}
findUser(req.body.userId);
```

Claude will call `scan-security` and show:

```
## ⚠️ Security Vulnerabilities Found!

### 🔴 Critical (1 issue)
- **Google API Key** (line 1)
  - Google API Key is hardcoded in the source code
  - 💡 Fix: Use environment variables and set API key restrictions

### 🟠 High (2 issues)
- **Template Literal SQL** (line 2)
  - SQL query uses template literals with variables
  - 💡 Fix: Use prepared statements

- **innerHTML Assignment** (line 3)
  - Dynamic value assigned to innerHTML
  - 💡 Fix: Use textContent or sanitize with DOMPurify

- **SQL query with user input** (line 6)
  - Function parameter taint reaches a SQL sink
  - 💡 Fix: Use prepared statements
```

Security Scanner MCP 1.2.0 uses AST-aware detection for JavaScript and TypeScript, so function parameters and multi-hop variable chains are detected. Literal HTML assigned to `innerHTML`, such as `el.innerHTML = '<div>safe</div>'`, is not reported as XSS.

## Step 2: Get Auto-Fix Suggestions

```
Me: Show me how to fix the innerHTML vulnerability
```

Claude will call `get-fix-suggestion` and provide:

```typescript
// ❌ Before (vulnerable)
element.innerHTML = userInput;

// ✅ After (safe)
element.textContent = userInput;

// Or if HTML is needed:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

## Step 3: Scan IaC Files

```
Me: Scan my Dockerfile for security issues
```

Claude will analyze your Dockerfile with:
- Built-in scanner rules
- Trivy (if Docker image is available)
- Checkov (if Docker image is available)

## Step 4: Generate Comprehensive Report

```
Me: Show me a full security report with Mermaid diagrams
```

Claude will call `generate-security-report` and create:

- Severity distribution pie chart
- Vulnerability category breakdown
- Attack scenario flowchart
- SARIF format for GitHub Code Scanning
- CVE/OWASP detailed information

## Available Tools

| Tool | Description |
|------|-------------|
| `scan-security` | Comprehensive security scan - runs all checks |
| `scan-secrets` | Detect hardcoded API keys, passwords, tokens |
| `scan-injection` | Find SQL/NoSQL/Command injection |
| `scan-xss` | Identify Cross-Site Scripting risks |
| `scan-crypto` | Check cryptographic weaknesses |
| `scan-auth` | Audit authentication/session security |
| `scan-path` | Find file/path vulnerabilities |
| `scan-dependencies` | Check for vulnerable dependencies |
| `scan-iac` | Scan Dockerfile, Kubernetes, Terraform |
| `get-fix-suggestion` | Get auto-generated fix code |
| `generate-security-report` | Create comprehensive reports |
| `scan-in-sandbox` | Run scans in Docker isolated environment |

## Tips

1. **Use `scan-security` for most cases** - it runs all scanners at once
2. **Use specific scanners** when you want to focus on one area
3. **Ask for fixes** after finding vulnerabilities
4. **Generate reports** for documentation or CI/CD integration
5. **Use sandbox** when scanning untrusted or potentially malicious code

## Common Workflows

### Workflow 1: Quick Check

```
Me: Scan this code for security issues
[paste code]
```

### Workflow 2: Deep Analysis

```
Me: Run a comprehensive security scan with detailed report
[paste code]
```

### Workflow 3: Safe Scanning

```
Me: Scan this code in a sandbox environment
[paste code]
```

## Next Steps

- [Basic Usage](./usage/basic-usage.md) - Learn all scanning features
- [IaC Scanning](./features/iac-scanning.md) - Scan infrastructure files
- [Sandbox Scanning](./features/sandbox.md) - Use Docker isolation
