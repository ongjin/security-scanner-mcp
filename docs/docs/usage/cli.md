---
sidebar_position: 2
---

# CLI Mode

Run Security Scanner MCP independently without Claude. Perfect for CI/CD pipelines like Jenkins, GitHub Actions, GitLab CI, and more.

## Installation

```bash
# Global installation
npm install -g security-scanner-mcp

# Or use npx (no installation required)
npx security-scanner-mcp scan ./src
```

## Commands

### scan

Scan files or directories for security vulnerabilities.

```bash
# Scan a single file
security-scanner-mcp scan ./src/app.js

# Scan a directory
security-scanner-mcp scan ./src

# Scan with specific language
security-scanner-mcp scan ./src --language typescript
```

### serve

Start as MCP server (for Claude Desktop/Code).

```bash
security-scanner-mcp serve
```

## Output Formats

### Text (Default)

Human-readable output with colors and formatting.

```bash
security-scanner-mcp scan ./src
```

Example output:
```
════════════════════════════════════════
       Security Scanner MCP Report
════════════════════════════════════════

📊 스캔 결과 요약
────────────────────────────────────────
   스캔된 파일: 5개
   발견된 취약점: 3개

   🔴 Critical: 1
   🟠 High: 2
   🟡 Medium: 0
   🟢 Low: 0
```

### JSON

Machine-readable format for parsing and automation.

```bash
security-scanner-mcp scan ./src --format json
```

Output structure:
```json
{
  "summary": {
    "totalFiles": 10,
    "scannedFiles": 10,
    "totalIssues": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "issues": [
    {
      "file": "./src/app.js",
      "line": 15,
      "severity": "critical",
      "type": "Hardcoded API Key",
      "message": "API key is hardcoded in source code",
      "fix": "Use environment variables",
      "owaspCategory": "A07:2021",
      "cweId": "CWE-798"
    }
  ]
}
```

### SARIF

GitHub Code Scanning compatible format.

```bash
security-scanner-mcp scan ./src --format sarif --output report.sarif
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <format>` | Output format (text, json, sarif) | text |
| `-o, --output <file>` | Save results to file | - |
| `-l, --language <lang>` | Programming language | auto |
| `-s, --severity <level>` | Minimum severity filter | low |
| `--fail-on <level>` | Exit code 1 if issues at this level | critical |
| `--include <patterns>` | File patterns to include | *.js,*.ts,*.py,*.java,*.go |
| `--exclude <patterns>` | Patterns to exclude | node_modules,dist,build,.git |
| `--no-color` | Disable colored output | - |

### Language Options

- `auto` - Auto-detect based on file extension
- `javascript` - JavaScript files
- `typescript` - TypeScript files
- `python` - Python files
- `java` - Java files
- `go` - Go files

### Severity Levels

- `critical` - Most severe vulnerabilities
- `high` - High severity
- `medium` - Medium severity
- `low` - Low severity (informational)

## CI/CD Integration

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan') {
            steps {
                sh 'npm install -g security-scanner-mcp'
                sh 'security-scanner-mcp scan ./src --format json --output security-report.json --fail-on high'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-report.json', fingerprint: true
        }
        failure {
            echo 'Security vulnerabilities detected!'
        }
    }
}
```

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run Security Scan
        run: |
          npx security-scanner-mcp scan ./src \
            --format sarif \
            --output results.sarif \
            --fail-on critical

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
stages:
  - test
  - security

security_scan:
  stage: security
  image: node:20-alpine
  script:
    - npm install -g security-scanner-mcp
    - security-scanner-mcp scan ./src --format json --output gl-security-report.json --fail-on high
  artifacts:
    reports:
      security: gl-security-report.json
    paths:
      - gl-security-report.json
    when: always
  allow_failure: false
```

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'
    displayName: 'Install Node.js'

  - script: |
      npm install -g security-scanner-mcp
      security-scanner-mcp scan ./src --format json --output $(Build.ArtifactStagingDirectory)/security-report.json --fail-on high
    displayName: 'Run Security Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/security-report.json'
      artifactName: 'SecurityReport'
    condition: always()
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Install Security Scanner
          command: npm install -g security-scanner-mcp
      - run:
          name: Run Security Scan
          command: |
            security-scanner-mcp scan ./src \
              --format json \
              --output security-report.json \
              --fail-on high
      - store_artifacts:
          path: security-report.json
          destination: security-report

workflows:
  version: 2
  build-and-scan:
    jobs:
      - security-scan
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success - No issues at or above `--fail-on` level |
| 1 | Failure - Issues found at or above `--fail-on` level |

## Examples

### Scan Only TypeScript Files

```bash
security-scanner-mcp scan ./src --include "*.ts,*.tsx"
```

### Exclude Test Files

```bash
security-scanner-mcp scan ./src --exclude "*.test.ts,*.spec.ts,__tests__"
```

### Show Only High and Critical Issues

```bash
security-scanner-mcp scan ./src --severity high
```

### Fail Build on Any High+ Issue

```bash
security-scanner-mcp scan ./src --fail-on high
```

### Generate Report for Code Review

```bash
security-scanner-mcp scan ./src --format json --output pr-security-report.json
```

## Pre-commit Hooks

### Using Husky

```bash
# Install husky
npm install --save-dev husky

# Initialize husky
npx husky init

# Add pre-commit hook
echo 'npx security-scanner-mcp scan ./src --fail-on high' > .husky/pre-commit
```

### Using lint-staged

```json
// package.json
{
  "lint-staged": {
    "*.{js,ts}": [
      "security-scanner-mcp scan --fail-on high"
    ]
  }
}
```

## Docker Usage

```bash
# Pull image
docker pull ongjin/security-scanner-mcp:latest

# Scan local files
docker run --rm \
  -v $(pwd):/code:ro \
  ongjin/security-scanner-mcp:latest \
  scan /code/src --format json
```

## Next Steps

- [MCP Tools](./mcp-tools.md) - Learn about MCP server tools
- [Integration](../advanced/integration.md) - Advanced CI/CD integration
- [Configuration](../reference/configuration.md) - Detailed configuration options
