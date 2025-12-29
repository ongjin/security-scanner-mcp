---
sidebar_position: 2
---

# Security Reporting

Generate comprehensive security reports with diagrams and industry-standard formats.

## Report Types

### Markdown Reports

Human-readable text format with:
- Executive summary
- Severity breakdown
- Detailed findings
- Remediation guidance

### Mermaid Diagrams

Visual representations:
- **Pie charts**: Severity distribution
- **Bar charts**: Vulnerability categories
- **Flowcharts**: Attack scenarios

### SARIF Format

Static Analysis Results Interchange Format:
- GitHub Code Scanning compatible
- VS Code integration
- CI/CD tooling support

## generate-security-report Tool

### Usage

```
Me: Generate a comprehensive security report

[Your code or scan results]
```

### Example Output

```markdown
# 🛡️ Security Scan Dashboard

## 📊 Overall Summary

**Total Vulnerabilities**: 8

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 2 | 25% |
| 🟠 High | 3 | 37.5% |
| 🟡 Medium | 2 | 25% |
| 🟢 Low | 1 | 12.5% |

## 🎯 Severity Distribution

\```mermaid
pie title Vulnerability Distribution by Severity
    "🔴 Critical" : 2
    "🟠 High" : 3
    "🟡 Medium" : 2
    "🟢 Low" : 1
\```

## 📦 Vulnerability Categories

\```mermaid
%%{init: {'theme':'base'}}%%
bar title Vulnerabilities by Category
    x-axis [Secrets, Injection, XSS, Crypto, Auth]
    y-axis "Count" 0 --> 5
    bar [2, 2, 1, 1, 2]
\```

## ⚔️ Potential Attack Scenarios

\```mermaid
flowchart TD
    Start([Attacker]) --> Recon[Reconnaissance]
    Recon --> Secrets[Hardcoded<br/>Secrets Found]
    Secrets --> Access[Bypass<br/>Authentication]
    Access --> Exploit[SQL Injection<br/>Exploitation]
    Exploit --> Data[Data<br/>Exfiltration]
    Data --> Impact[Business<br/>Impact]
\```

## 🔴 Critical Issues

### 1. Hardcoded AWS Credentials
- **File**: config.js
- **Line**: 12
- **CWE**: CWE-798
- **OWASP**: A07:2021
- **Fix**: Use AWS SDK with IAM roles

## 🟠 High Severity Issues

[Detailed findings...]

## 📋 SARIF Report

SARIF JSON compatible with GitHub Code Scanning, VS Code, and other tools.

\```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Security Scanner MCP",
        "version": "1.0.0"
      }
    },
    "results": [...]
  }]
}
\```
```

## CVE/OWASP Integration

Reports include:

### CVE Information
- CVE ID
- CVSS score
- Affected versions
- Fix version
- References

### OWASP Top 10 Mapping
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery

## GitHub Integration

### Code Scanning Alerts

Upload SARIF to GitHub:

```bash
# Generate SARIF
curl -X POST https://api.github.com/repos/OWNER/REPO/code-scanning/sarifs \
  -H "Authorization: token $GITHUB_TOKEN" \
  -d @report.sarif.json
```

### Actions Integration

```yaml
- name: Security Scan
  run: |
    # Generate SARIF report
    # Upload to GitHub
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: security-report.sarif
```

## Report Customization

### Filter by Severity

```
Me: Generate a report showing only critical and high severity issues
```

### Focus on Categories

```
Me: Create a report focusing on injection vulnerabilities
```

### Include Remediation

```
Me: Generate a report with detailed fix instructions
```

## Export Formats

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

Interactive HTML report with:
- Sortable tables
- Filterable results
- Clickable references
- Responsive design

## Best Practices

1. **Generate regularly**: After each major code change
2. **Track trends**: Compare reports over time
3. **Share with team**: Include in code reviews
4. **CI/CD integration**: Automated report generation
5. **Document fixes**: Update reports as issues are resolved

## Report Templates

### Executive Summary Template

```markdown
# Security Assessment Report

**Project**: [Name]
**Date**: [Date]
**Scanned by**: Security Scanner MCP

## Executive Summary

This assessment identified [X] security vulnerabilities across [Y] files.
Immediate action is required for [Z] critical issues.

## Key Findings

1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

## Recommendations

1. [Recommendation 1]
2. [Recommendation 2]
```

### Technical Report Template

```markdown
# Technical Security Analysis

## Methodology
- Static analysis
- Pattern matching
- External tool integration (Trivy, Checkov, GitLeaks)

## Scope
- [Files scanned]
- [Languages analyzed]
- [Rule sets applied]

## Detailed Findings
[Technical details...]
```

## Next Steps

- [Integration](./integration.md) - CI/CD integration
- [External Tools](./external-tools.md) - Enhanced scanning
- [Configuration](../reference/configuration.md) - Report customization
