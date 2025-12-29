---
sidebar_position: 4
---

# Docker Sandbox Scanning

Run security scans in an isolated Docker environment for maximum safety.

## Why Use Sandbox?

Protect your host system from potentially malicious code:
- ✅ **Isolated execution** - Code runs in containerized environment
- ✅ **Resource limits** - CPU, memory, and time constraints
- ✅ **Network isolation** - No external network access
- ✅ **Read-only filesystem** - Cannot modify host files
- ✅ **Enhanced scanning** - Uses external tools (Trivy, Checkov, GitLeaks)

## Setup

### Pull from Docker Hub (Recommended)

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### Or Build from Source

```bash
npm run docker:build
```

**Note**: Building takes 5-10 minutes and creates a ~500MB image with:
- Trivy v0.50.4
- GitLeaks v8.18.4
- Checkov (Python-based)

## Usage

### Basic Sandbox Scan

```
Me: Scan this code in a sandbox

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claude will call `scan-in-sandbox` which:
1. Writes code to temporary file
2. Launches Docker container
3. Runs all scanners inside container
4. Returns results as JSON
5. Cleans up container

### Scan Untrusted Code

```
Me: This code looks suspicious, scan it safely

[paste potentially malicious code]
```

## Security Configuration

### Default Settings

```
Memory Limit: 512MB
CPU Limit: 0.5 cores
Timeout: 30 seconds
Network: Disabled
Filesystem: Read-only (except /tmp)
Capabilities: Dropped (no-new-privileges)
```

### Customizable Options

You can adjust these through environment variables:

```bash
SANDBOX_MEMORY=1g \
SANDBOX_CPU=1.0 \
SANDBOX_TIMEOUT=60000 \
scan-in-sandbox
```

## Scanners Available in Sandbox

### Built-in Scanners
- Secret detection
- SQL/NoSQL/Command injection
- XSS vulnerabilities
- Cryptographic issues
- Authentication problems
- Path traversal

### External Tools (Docker only)
- **GitLeaks**: Enhanced secret detection with entropy analysis
- **Trivy**: IaC and container vulnerability scanning
- **Checkov**: Infrastructure as Code security analysis

## Docker Container Details

### Base Image
```dockerfile
FROM node:20-alpine
```

### Security Hardening

```dockerfile
# Non-root user
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner

# Read-only root filesystem
# No new privileges
# Dropped capabilities
# Network disabled
```

### Installed Tools

```bash
# Verify tools are installed
docker run security-scanner-mcp:latest sh -c "
  trivy --version &&
  gitleaks version &&
  checkov --version
"
```

## Results Format

Sandbox scan returns comprehensive JSON:

```json
{
  "success": true,
  "language": "javascript",
  "filename": "code.js",
  "issuesCount": 3,
  "issues": [
    {
      "type": "Google API Key",
      "severity": "critical",
      "message": "Google API Key is hardcoded",
      "fix": "Use environment variables",
      "line": 1,
      "metadata": {
        "tool": "gitleaks",
        "ruleId": "google-api-key",
        "entropy": 4.2
      }
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

## Performance Considerations

### Container Startup
- **First run**: ~2-3 seconds (cold start)
- **Subsequent runs**: ~1 second (cached)

### Scan Duration
- **Small files (under 100 lines)**: Less than 5 seconds
- **Medium files (100-500 lines)**: 5-15 seconds
- **Large files (over 500 lines)**: 15-30 seconds

### Resource Usage
- **Memory**: Approximately 100-200MB per scan
- **CPU**: Minimal (0.1-0.5 cores)
- **Disk**: Temporary files cleaned automatically

## Troubleshooting

### Container Not Found

```bash
# Check if image exists
docker images | grep security-scanner-mcp

# Pull if missing
docker pull ongjin/security-scanner-mcp:latest
```

### Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart shell
```

### Timeout Issues

```bash
# Increase timeout (ms)
SANDBOX_TIMEOUT=60000 scan-in-sandbox
```

## Best Practices

1. **Use for untrusted code**: Always scan code from unknown sources
2. **Regular image updates**: Pull latest security updates monthly
3. **Monitor resource usage**: Prevent abuse with limits
4. **Cleanup**: Containers are auto-removed, but check periodically
5. **Network isolation**: Keep network disabled unless required

## Advanced Configuration

### Custom Docker Image

```dockerfile
FROM security-scanner-mcp:latest

# Add custom scanners
RUN pip3 install custom-scanner

# Add custom rules
COPY custom-rules.yaml /app/rules/
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Scan Code in Sandbox
  run: |
    docker pull ongjin/security-scanner-mcp:latest
    docker run --rm \
      -v ${{ github.workspace }}:/code:ro \
      security-scanner-mcp:latest \
      scan /code
```

## Next Steps

- [External Tools](../advanced/external-tools.md) - Learn about Trivy, Checkov, GitLeaks
- [Reporting](../advanced/reporting.md) - Generate SARIF reports
- [Integration](../advanced/integration.md) - Integrate with CI/CD
