---
sidebar_position: 1
---

# External Security Tools

Learn about the industry-standard tools integrated with Security Scanner MCP.

## Overview

When running in Docker sandbox mode, Security Scanner MCP leverages three powerful external tools to enhance detection capabilities:

- **Trivy** - Container and IaC vulnerability scanner
- **Checkov** - Infrastructure as Code security analysis
- **GitLeaks** - Secret detection with entropy analysis

## Trivy

### About

- **Version**: 0.50.4
- **Developer**: Aqua Security
- **License**: Apache 2.0
- **Website**: https://trivy.dev

### Capabilities

**Container Scanning**:
- OS package vulnerabilities
- Application dependencies
- Known CVEs

**IaC Scanning**:
- Dockerfile misconfigurations
- Kubernetes manifests
- Terraform/CloudFormation

**Features**:
- Comprehensive CVE database
- Fast scanning (seconds)
- Multiple output formats
- Air-gapped support

### Integration

Trivy runs automatically for IaC files when using `scan-in-sandbox`:

```
Me: Scan this Dockerfile in sandbox

FROM node:latest
ENV SECRET="abc123"
```

Results include Trivy findings with:
- CVE identifiers
- CVSS scores
- Fix versions
- References

### Configuration

Custom Trivy scanning:

```bash
# Severity filtering
docker run security-scanner-mcp trivy --severity HIGH,CRITICAL

# Skip unfixed vulnerabilities  
docker run security-scanner-mcp trivy --ignore-unfixed
```

## Checkov

### About

- **Developer**: Bridgecrew (Palo Alto Networks)
- **License**: Apache 2.0
- **Website**: https://www.checkov.io

### Capabilities

**Supported Frameworks**:
- Terraform
- CloudFormation
- Kubernetes
- Dockerfile
- Azure ARM Templates
- Helm Charts

**Policy Coverage**:
- 1000+ built-in policies
- CIS Benchmarks
- PCI-DSS
- HIPAA
- SOC 2

**Features**:
- Graph-based scanning
- Custom policy support
- Fix suggestions
- Suppression comments

### Integration

Checkov scans IaC files automatically:

```
Me: Check this Terraform file

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # Missing encryption
}
```

Results include:
- Policy ID (CKV_AWS_*)
- Guideline links
- Fix recommendations
- Compliance mappings

### Custom Policies

Add custom Checkov policies:

```python
# custom_policy.py
from checkov.common.models.enums import CheckResult

class CustomCheck(BaseResourceCheck):
    def scan_resource_conf(self, conf):
        # Your custom logic
        return CheckResult.PASSED
```

## GitLeaks

### About

- **Version**: 8.18.4
- **Developer**: Zachary Rice
- **License**: MIT
- **Website**: https://github.com/gitleaks/gitleaks

### Capabilities

**Detection Methods**:
- Regex patterns
- Entropy analysis
- Shannon entropy
- File path scanning

**Supported Secrets**:
- API keys (1000+ services)
- Private keys
- Tokens and passwords
- Connection strings
- Cloud credentials

**Features**:
- Low false positive rate
- Fast scanning
- Custom rules support
- JSON/SARIF output

### Integration

GitLeaks enhances secret detection:

```javascript
// Our built-in scanner detects patterns
const apiKey = "AIzaSyC123...";

// GitLeaks adds:
// - Entropy score (4.2)
// - Rule ID (google-api-key)
// - Confidence level (high)
```

### Custom Rules

Add custom GitLeaks rules:

```toml
# .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''custom_[0-9a-zA-Z]{32}'''
tags = ["api", "custom"]
```

## Performance Comparison

| Tool | Speed | Accuracy | Coverage |
|------|-------|----------|----------|
| Built-in Scanners | ⚡⚡⚡ Very Fast | ⭐⭐⭐ Good | ⭐⭐ Moderate |
| GitLeaks | ⚡⚡ Fast | ⭐⭐⭐⭐ Excellent | ⭐⭐⭐ Extensive |
| Trivy | ⚡⚡ Fast | ⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐ Comprehensive |
| Checkov | ⚡ Moderate | ⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐ Comprehensive |

## Best Practices

### When to Use External Tools

✅ **Use sandbox + external tools for**:
- Production code review
- Pre-deployment scanning
- Compliance requirements
- Unknown/untrusted code

⚡ **Use built-in scanners for**:
- Quick development checks
- IDE integration
- Immediate feedback
- Offline scanning

### Optimization Tips

1. **Cache Docker images**: Pull once, use many times
2. **Parallel scanning**: Run tools concurrently
3. **Filter results**: Focus on high/critical severity
4. **Update regularly**: New rules and CVEs added monthly

### Security Considerations

All external tools run in isolated Docker containers with:
- ✅ Read-only filesystem
- ✅ No network access
- ✅ Limited CPU/memory
- ✅ No new privileges
- ✅ Dropped capabilities

## Updates

### Checking Versions

```bash
docker run security-scanner-mcp sh -c "
  trivy --version
  gitleaks version
  checkov --version
"
```

### Updating Tools

```bash
# Pull latest image with updated tools
docker pull ongjin/security-scanner-mcp:latest
```

## Tool Output Examples

### Trivy Output

```json
{
  "Type": "dockerfile",
  "ID": "CIS-DI-0001",
  "Title": "Create a user for the container",
  "Severity": "HIGH",
  "Resolution": "Add USER instruction"
}
```

### Checkov Output

```json
{
  "check_id": "CKV_AWS_18",
  "check_name": "Ensure S3 bucket has server-side encryption",
  "severity": "HIGH",
  "guideline": "https://..."
}
```

### GitLeaks Output

```json
{
  "Description": "Google API Key",
  "RuleID": "google-api-key",
  "Entropy": 4.2,
  "Match": "AIza...abc",
  "Secret": "AIzaSyC1234567890abcdef"
}
```

## Next Steps

- [Reporting](./reporting.md) - Generate comprehensive reports
- [Integration](./integration.md) - CI/CD integration
- [Sandbox](../features/sandbox.md) - Learn about Docker isolation
