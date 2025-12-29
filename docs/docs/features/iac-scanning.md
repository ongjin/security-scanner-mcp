---
sidebar_position: 2
---

# Infrastructure as Code (IaC) Scanning

Scan your infrastructure configuration files for security misconfigurations.

## Supported IaC Formats

### 🐳 Dockerfile

**15+ rules based on CIS Docker Benchmark**

Common issues detected:
- Running containers as root
- Hardcoded secrets in ENV or ARG
- Using `latest` tag
- Unnecessary port exposure
- Missing health checks
- Running apt-get update without cleanup
- Using ADD instead of COPY
- Missing USER instruction

**Example:**

```dockerfile
# ❌ Vulnerable
FROM node:latest
ENV API_KEY="secret123"
RUN apt-get update && apt-get install -y curl
EXPOSE 22
# No USER instruction - runs as root

# ✅ Secure
FROM node:20-alpine
ARG API_KEY
RUN apk add --no-cache curl && \
    rm -rf /var/cache/apk/*
EXPOSE 3000
USER node
HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1
```

### ☸️ Kubernetes

**13+ rules based on Pod Security Standards**

Common issues detected:
- Privileged containers
- Running as root
- Host network/PID/IPC usage
- Dangerous capability additions (SYS_ADMIN, NET_ADMIN)
- Missing resource limits
- Read-write root filesystem
- Privileged escalation allowed
- Host path mounts

**Example:**

```yaml
# ❌ Vulnerable
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
    resources: {}

# ✅ Secure
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
```

### 🏗️ Terraform

**15+ rules for AWS/GCP/Azure**

Common issues detected:
- Public IP assignment to sensitive resources
- Encryption disabled for storage/databases
- Security groups open to 0.0.0.0/0
- Publicly accessible S3 buckets
- Missing VPC flow logs
- Unencrypted EBS volumes
- IAM policies with wildcards
- Missing MFA for sensitive operations

**Example:**

```hcl
# ❌ Vulnerable
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ Secure
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
}
```

## Usage

### Basic IaC Scan

```
Me: Scan my Dockerfile for security issues

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update && apt-get install curl
```

### Scan Kubernetes YAML

```
Me: Check this Kubernetes manifest for security problems

[paste YAML]
```

### Scan Terraform Configuration

```
Me: Review this Terraform file for security misconfigurations

[paste .tf file]
```

## External Tools Integration

When using Docker sandbox (`scan-in-sandbox`), additional industry-standard tools are used:

### Trivy
- **Version**: 0.50.4
- **Purpose**: Container and IaC vulnerability scanner
- Comprehensive misconfiguration detection
- CVE database integration

### Checkov
- **Purpose**: IaC security scanner
- 1000+ built-in policies
- Compliance frameworks (CIS, PCI-DSS, HIPAA)
- Multi-cloud support

## Scan Results

Results include:
- **Rule ID**: Specific misconfiguration identifier
- **Severity**: Critical, High, Medium, Low
- **Description**: What the issue is
- **Fix**: How to remediate
- **OWASP Category**: Mapped to OWASP Top 10
- **CWE ID**: Common Weakness Enumeration

## Best Practices

1. **Scan early**: Include in CI/CD pipeline
2. **Use specific versions**: Avoid `latest` tags
3. **Follow least privilege**: Minimal permissions
4. **Enable encryption**: For data at rest and in transit
5. **Regular updates**: Keep base images and dependencies current

## Next Steps

- [Auto-Fix](./auto-fix.md) - Get automatic remediation suggestions
- [Sandbox Scanning](./sandbox.md) - Run in Docker isolated environment
- [External Tools](../advanced/external-tools.md) - Learn about Trivy and Checkov
