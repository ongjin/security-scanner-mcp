---
sidebar_position: 2
---

# Installation

## Install from npm (Recommended)

```bash
npm install -g security-scanner-mcp
```

## Or build from source

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## Register with Claude Code

### After global npm install

```bash
claude mcp add --scope project security-scanner -- security-scanner-mcp
```

### Or if built from source

```bash
claude mcp add --scope project security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## Quick Setup (Auto-approve tools)

If you find it tedious to approve tool usage every time, set up auto-approval:

### 🖥️ Claude Desktop App Users

1. Restart the Claude app.
2. Ask a question that uses the `security-scanner` tool.
3. When the notification appears, check **"Always allow requests from this server"** and click **Allow**.

### ⌨️ Claude Code (CLI) Users

1. Run `claude` in your terminal.
2. Type `/permissions` in the prompt and press Enter.
3. Select **Global Permissions** (or Project Permissions) > **Allowed Tools**.
4. Enter `mcp__security-scanner__scan-security` for just the main tool, or `mcp__security-scanner__*` to allow all tools.

> 💡 **Tip**: In most cases, allowing **`scan-security`** alone is sufficient, as it performs all security checks in one go.

## Docker Setup (Optional)

For sandbox scanning, you'll need Docker:

### Pull from Docker Hub (Recommended)

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### Or build from source

```bash
npm run docker:build
```

> Note: Building takes 5-10 minutes and the image size is approximately 500MB.

The Docker image includes:
- **Trivy v0.50.4** - Container/IaC vulnerability scanner
- **GitLeaks v8.18.4** - Secret detection
- **Checkov** - Infrastructure as Code security scanner

## Verify Installation

```bash
# Check if installed correctly
security-scanner-mcp --version

# Or if built from source
node dist/index.js --version
```

## System Requirements

- **Node.js**: >= 18.0.0
- **npm**: >= 9.0.0
- **Docker** (optional, for sandbox scanning)

## Next Steps

- [Quick Start](./quick-start.md) - Get started in 5 minutes
- [Basic Usage](./usage/basic-usage.md) - Learn how to scan code
