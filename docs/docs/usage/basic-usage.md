---
sidebar_position: 1
---

# Basic Usage

Learn how to use Security Scanner MCP with Claude.

## Quick Scan

The simplest way to scan code:

```
Me: Scan this code for security issues

const apiKey = "sk_live_1234567890";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claude will automatically call the `scan-security` tool and show results.

## Scan Results Format

Results are organized by severity:

```
## ⚠️ Security Vulnerabilities Found!

### 🔴 Critical (1 issue)
- **Stripe API Key** (line 1)
  - Stripe Live API key is hardcoded in source code
  - 💡 Fix: Store in environment variables

### 🟠 High (1 issue)
- **Template Literal SQL** (line 2)
  - SQL query uses template literals with user input
  - 💡 Fix: Use prepared statements with placeholders
```

## Scan Different File Types

### JavaScript/TypeScript

```
Me: Check this TypeScript code

interface User {
  password: string;
}

const user: User = {
  password: "admin123"  // Hardcoded password
};
```

### Python

```
Me: Scan this Python code

import os

# Vulnerable
db_password = "mypassword123"
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### Java

```
Me: Review this Java code

public class Config {
    private static final String API_KEY = "abc123";

    public void query(String userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
    }
}
```

### Go

```
Me: Check this Go code

package main

const apiKey = "sk_test_1234567890"

func query(userId string) {
    sql := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)
}
```

## Scan Infrastructure Files

### Dockerfile

```
Me: Scan this Dockerfile

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update
EXPOSE 22
```

### Kubernetes

```
Me: Check this Kubernetes manifest

apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
```

### Terraform

```
Me: Review this Terraform config

resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
```

## Understanding Results

### Severity Levels

- 🔴 **Critical**: Immediate action required (e.g., exposed API keys)
- 🟠 **High**: Serious vulnerability (e.g., SQL injection)
- 🟡 **Medium**: Important to fix (e.g., weak encryption)
- 🟢 **Low**: Should be addressed (e.g., missing best practices)

### Issue Details

Each issue includes:
- **Type**: Vulnerability category
- **Line number**: Where it was found
- **Message**: What the problem is
- **Fix**: How to remediate
- **OWASP Category**: Security classification
- **CWE ID**: Common Weakness Enumeration

## Common Workflows

### Workflow 1: Quick Check Before Commit

```
Me: Quick security check on this code before I commit

[paste code]
```

### Workflow 2: Deep Analysis

```
Me: Do a comprehensive security analysis

[paste code]

Me: Show me how to fix the SQL injection issue

Me: Generate a full security report
```

### Workflow 3: Infrastructure Review

```
Me: Review my Dockerfile for security issues

[paste Dockerfile]

Me: Also check this Kubernetes deployment

[paste YAML]
```

### Workflow 4: Untrusted Code

```
Me: I found this code online, is it safe?

[paste code]

Me: Scan it in a sandbox to be safe
```

## Tips for Better Results

1. **Provide context**: Mention the language/framework
2. **Include enough code**: Scanners need context
3. **Ask for specific checks**: Use targeted tools for focused analysis
4. **Request fixes**: Ask "how do I fix this?" after scanning
5. **Generate reports**: Use `generate-security-report` for documentation

## False Positives

If you encounter a false positive:

```
Me: This detected an API key but it's actually a placeholder

Claude: I understand. The scanner detected the pattern but context matters.
[Explains why it was flagged]
```

## Next Steps

- [CLI Usage](./cli.md) - Use command-line interface
- [MCP Tools](./mcp-tools.md) - Learn about all available tools
- [Auto-Fix](../features/auto-fix.md) - Get fix suggestions
