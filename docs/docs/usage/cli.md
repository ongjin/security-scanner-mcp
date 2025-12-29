---
sidebar_position: 2
---

# Command Line Interface

Use Security Scanner MCP directly from the command line.

## Installation

```bash
# Global installation
npm install -g security-scanner-mcp

# Or use npx
npx security-scanner-mcp
```

## Basic Commands

### Version Information

```bash
security-scanner-mcp --version
```

### Help

```bash
security-scanner-mcp --help
```

## Standalone Usage

While Security Scanner MCP is designed to work with Claude Code, you can also use it programmatically:

```javascript
import { scanSecrets, scanInjection, scanXss } from 'security-scanner-mcp';

const code = `
  const apiKey = "AIzaSyC1234567890";
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
`;

// Scan for secrets
const secretIssues = scanSecrets(code);

// Scan for injection
const injectionIssues = scanInjection(code, 'javascript');

// Scan for XSS
const xssIssues = scanXss(code, 'javascript');

console.log('Total issues:', [
  ...secretIssues,
  ...injectionIssues,
  ...xssIssues
].length);
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Security Scanner
        run: npm install -g security-scanner-mcp

      - name: Run Security Scan
        run: |
          # Scan all JavaScript files
          find . -name "*.js" -not -path "*/node_modules/*" | while read file; do
            echo "Scanning $file"
            # Your scan logic here
          done
```

### GitLab CI

```yaml
security-scan:
  image: node:20-alpine
  before_script:
    - npm install -g security-scanner-mcp
  script:
    - echo "Running security scans..."
    # Add your scan commands
  only:
    - merge_requests
    - main
```

## Docker Usage

### Direct Docker Run

```bash
# Pull image
docker pull ongjin/security-scanner-mcp:latest

# Scan a file
docker run --rm \
  -v $(pwd):/code:ro \
  ongjin/security-scanner-mcp:latest \
  scan /code/myfile.js
```

### Docker Compose

```yaml
version: '3.8'
services:
  security-scanner:
    image: ongjin/security-scanner-mcp:latest
    volumes:
      - ./src:/code:ro
    command: scan /code
```

## Configuration Files

### .securityscannerrc

Create a configuration file in your project root:

```json
{
  "exclude": [
    "node_modules/**",
    "dist/**",
    "*.test.js"
  ],
  "severity": {
    "minLevel": "medium"
  },
  "rules": {
    "secrets": true,
    "injection": true,
    "xss": true,
    "crypto": true
  }
}
```

## Environment Variables

Configure behavior with environment variables:

```bash
# Sandbox settings
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# Scanner settings
export SCANNER_VERBOSE=true
export SCANNER_OUTPUT=json
```

## Exit Codes

The CLI uses standard exit codes:

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected
- `2`: Scan error

Use in scripts:

```bash
#!/bin/bash
security-scanner-mcp scan myfile.js
if [ $? -eq 1 ]; then
  echo "Vulnerabilities found!"
  exit 1
fi
```

## Pre-commit Hooks

### Using Husky

```bash
# Install husky
npm install --save-dev husky

# Add pre-commit hook
npx husky add .husky/pre-commit "npm run security-scan"
```

```json
// package.json
{
  "scripts": {
    "security-scan": "security-scanner-mcp scan src/"
  }
}
```

## VS Code Integration

Create a VS Code task (`.vscode/tasks.json`):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "security-scanner-mcp",
      "args": ["scan", "${file}"],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": []
    }
  ]
}
```

## Next Steps

- [MCP Tools](./mcp-tools.md) - Learn about MCP server tools
- [Integration](../advanced/integration.md) - Advanced CI/CD integration
- [Configuration](../reference/configuration.md) - Detailed configuration options
