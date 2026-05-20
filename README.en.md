# 🔒 Security Scanner MCP

Your **intelligent security partner** that automatically detects vulnerabilities in AI-generated code and suggests fixes.

[![npm version](https://img.shields.io/npm/v/security-scanner-mcp)](https://www.npmjs.com/package/security-scanner-mcp)
[![npm downloads](https://img.shields.io/npm/dm/security-scanner-mcp)](https://www.npmjs.com/package/security-scanner-mcp)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://ongjin.github.io/security-scanner-mcp)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

**[English](#english)** | **[한국어](README.md)** | **[📚 Documentation](https://ongjin.github.io/security-scanner-mcp)**

## Demo

<!-- Add your demo GIF here -->
![Security Scanner Demo](./docs/demo.gif)

## Why do you need this?

Research shows that AI-generated code contains **322% more security vulnerabilities** than human-written code.

This MCP server goes beyond simple scanning:
- 💡 **Auto-generates fix suggestions** for vulnerabilities
- 🏗️ **Scans IaC files** (Dockerfile, Kubernetes, Terraform)
- 📊 **Creates Mermaid diagrams and SARIF reports** for visualization
- 🐳 **Runs safely in Docker sandbox** for isolation

**One scan before commit, one scan before deploy.** That's all you need.

## ✨ Key Features

### 🎯 Code Security Scanning
| Tool | Description |
|------|-------------|
| `scan-security` | **Comprehensive security scan** - runs all checks at once |
| `scan-secrets` | Detect hardcoded API keys, passwords, and tokens |
| `scan-injection` | Find SQL/NoSQL/Command injection vulnerabilities |
| `scan-xss` | Identify Cross-Site Scripting risks |
| `scan-crypto` | Check cryptographic weaknesses (weak hashes, insecure random, etc.) |
| `scan-auth` | Audit authentication/session security (JWT, cookies, CORS) |
| `scan-path` | Find file/path vulnerabilities (Path Traversal, uploads, etc.) |
| `scan-dependencies` | Check for vulnerable dependencies in package.json |

#### 1.2.0 AST-aware JS/TS detection

JavaScript and TypeScript scanners now parse ASTs so they can follow data flow that regex-only scanning missed.

- Function-parameter taint: `h(req.body.x)` is detected when `function h(input) { db.query(input); }` sends that parameter to a sink.
- Multi-hop variables: `req.body` → `a` → `b` → sink flows are detected.
- `innerHTML` reports dynamic assignments, while literal HTML strings are no longer reported as XSS findings.
- `res.setHeader('Access-Control-Allow-Origin', '*')` CORS wildcards are detected.
- Python / Java / Go inputs, and JS/TS files that fail to parse, continue through the existing regex path.

### 🏗️ Infrastructure as Code (IaC) Scanning
| Tool | Description |
|------|-------------|
| `scan-iac` | Security scanning for **Dockerfile, Kubernetes, Terraform** |

- **Dockerfile**: 15 rules based on CIS Docker Benchmark
- **Kubernetes**: 13 rules based on Pod Security Standards (PSS)
- **Terraform**: 15 rules for AWS/GCP/Azure security configurations

### 🛠️ Auto-Fix & Advanced Features
| Tool | Description |
|------|-------------|
| `get-fix-suggestion` | **Auto-generate fixed code** for detected vulnerabilities |
| `generate-security-report` | Create comprehensive reports with **Mermaid diagrams + SARIF + CVE info** |
| `scan-in-sandbox` | Run scans safely in **Docker isolated environment** |

## Installation

### Install from npm (Recommended)

```bash
npm install -g security-scanner-mcp
```

### Or build from source

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## Register with Claude Code

```bash
# After global npm install
claude mcp add --scope project security-scanner -- security-scanner-mcp

# Or if built from source
claude mcp add --scope project security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## Quick Setup (Auto-approve tools)

If you find it tedious to approve tool usage every time, set up auto-approval:

### 🖥️ Claude Desktop App Users
1. Restart the Claude app.
2. Ask a question that uses the `security-scanner` tool.
3. When the notification appears, check **"Always allow requests from this server"** and click **Allow**.
   (You won't be asked again.)

### ⌨️ Claude Code (CLI) Users
If you're using the terminal environment (`claude` command), use permission management commands:

1. Run `claude` in your terminal.
2. Type `/permissions` in the prompt and press Enter.
3. Select **Global Permissions** (or Project Permissions) > **Allowed Tools**.
4. Enter `mcp__security-scanner__scan-security` for just the main tool, or `mcp__security-scanner__*` to allow all tools.

> 💡 **Tip**: In most cases, allowing **`scan-security`** alone is sufficient, as it performs all security checks in one go.

## Usage Examples

### 📝 Basic Code Scan

```
Me: Scan this code for security issues

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

Claude: [calls scan-security]

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
```

### 🛠️ Get Auto-Fix Suggestions

```
Me: Show me how to fix the innerHTML vulnerability

Claude: [calls get-fix-suggestion]

## ✅ Fixed Code

// ❌ Before (vulnerable)
element.innerHTML = userInput;

// ✅ After (safe)
element.textContent = userInput;
// Or if HTML is needed:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 🏗️ IaC File Scanning

```
Me: Scan my Dockerfile for security issues

Claude: [calls scan-iac]

## 🐳 Dockerfile Security Vulnerabilities Found!

### 🔴 Critical (2 issues)
- **DOC001**: Running as root user
  - 💡 Fix: Set non-root user with USER command

- **DOC005**: Hardcoded secrets
  - 💡 Fix: Use ARG and build secrets

### 🟠 High (3 issues)
- **DOC002**: Using latest tag
  - 💡 Fix: Use explicit version tags (e.g., node:20-alpine)
...
```

### 📊 Generate Comprehensive Report

```
Me: Show me a full security report with Mermaid diagrams

Claude: [calls generate-security-report]

# 🛡️ Security Scan Dashboard

## 📊 Overall Summary
**8 vulnerabilities** found in total.

## 🎯 Severity Distribution
```mermaid
pie title Vulnerability Distribution by Severity
    "🔴 Critical" : 2
    "🟠 High" : 3
    "🟡 Medium" : 2
    "🟢 Low" : 1
\```

## ⚔️ Potential Attack Scenarios
```mermaid
flowchart TD
    Start([Attacker]) --> Recon[Reconnaissance]
    Recon --> Secrets[Hardcoded<br/>Secrets Found]
    Secrets --> Access[Bypass Auth]
    ...
\```

+ SARIF Report (GitHub Code Scanning compatible)
+ CVE/OWASP detailed information
```

### 🐳 Sandbox Scanning

```
Me: Scan this code safely in a sandbox

Claude: [calls scan-in-sandbox]

## 🐳 Sandbox Scan Results

✅ **Scan Complete**

### 🔒 Sandbox Configuration
- **Memory Limit**: 512MB
- **CPU Limit**: 0.5 cores
- **Timeout**: 30000ms
- **Network**: Disabled
- **Privileges**: Minimal
```

## Detected Vulnerabilities

### 🔑 Hardcoded Secrets
- AWS Access Key / Secret Key
- Google API Key / OAuth Secret
- GitHub Token / Slack Token
- Database Connection Strings
- Private Keys (RSA, EC, etc.)
- JWT Tokens
- Kakao / Naver API Keys
- Stripe / Twilio API Keys

### 💉 Injection Attacks
- SQL Injection (string concatenation, template literals, function-parameter flow)
- NoSQL Injection (MongoDB, tainted query objects)
- Command Injection (exec, spawn, execSync)
- LDAP Injection

### 🌐 Cross-Site Scripting (XSS)
- dangerouslySetInnerHTML (React)
- innerHTML / outerHTML (dynamic assignments detected, literal HTML excluded)
- jQuery .html() / Vue v-html
- eval() / new Function()
- document.write()

### 🔐 Cryptographic Issues
- Weak hashing (MD5, SHA1)
- Insecure random (Math.random)
- Plain password storage through multi-hop taint
- Hardcoded encryption keys/IVs
- SSL certificate validation disabled
- Vulnerable TLS versions (1.0, 1.1)

### 🔒 Authentication & Sessions
- JWT misconfigurations (none algorithm, no expiration)
- Insecure cookie settings
- CORS wildcards, including `setHeader` / `header`
- Weak password policies

### 📁 File & Path Issues
- Path Traversal, including multi-hop variable and function-parameter flow
- Dangerous file deletions
- Insecure file uploads
- Zip Slip (Java)
- Pickle deserialization (Python)

### 🏗️ Infrastructure as Code
**Dockerfile** (CIS Docker Benchmark):
- Running as root
- Hardcoded secrets
- Using latest tags
- Unnecessary port exposure
- Missing health checks

**Kubernetes** (Pod Security Standards):
- Privileged containers
- Root execution
- Host network/PID/IPC usage
- Dangerous capability additions
- Missing resource limits

**Terraform** (Multi-Cloud):
- Public IP assignment
- Encryption disabled
- Firewall open to all (0.0.0.0/0)
- Publicly accessible resources

### 📦 Vulnerable Dependencies
- npm audit integration
- Python requirements.txt scanning
- Go go.mod scanning

## Supported Languages

- ✅ JavaScript / TypeScript
- ✅ Python
- ✅ Java
- ✅ Go
- ✅ Dockerfile
- ✅ Kubernetes YAML
- ✅ Terraform HCL

## 🎨 Report Formats

- **Markdown**: Human-readable text reports
- **Mermaid**: Visual diagrams (Pie, Bar, Flowchart)
- **SARIF**: GitHub Code Scanning / VS Code compatible format
- **CVE Enrichment**: NVD database integration
- **OWASP Mapping**: OWASP Top 10:2021 + CWE mapping

## 🐳 Docker Sandbox

Protect your host system from potentially malicious code by running scans in an isolated Docker environment.

### Prepare Docker Image

#### Pull from Docker Hub (Recommended)

```bash
# Download pre-built image (includes Trivy, GitLeaks, Checkov)
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

**Included External Security Tools**:
- Trivy v0.50.4 - Container/IaC vulnerability scanner
- GitLeaks v8.18.4 - Secret detection
- Checkov - Infrastructure as Code security scanner

#### Build from Source (Optional)

```bash
npm run docker:build
```

> Note: Building takes 5-10 minutes and the image size is approximately 500MB.

### Run Sandbox Scan

From Claude Code:
```
scan-in-sandbox invocation
```

**Security Settings**:
- Memory limit: 128MB ~ 2GB
- CPU limit: 0.1 ~ 2.0 cores
- Timeout: 5s ~ 5min
- Network: Disabled by default
- Filesystem: Read-only
- Privileges: Minimal (no-new-privileges, drop all capabilities)

## Demo

```bash
# Run demo
npm run demo
```

## Architecture

```
src/
├── index.ts                    # MCP server (12 tools)
├── scanners/                   # Code scanners (8)
│   ├── secrets.ts
│   ├── injection.ts
│   ├── xss.ts
│   └── ...
├── iac-scanners/              # IaC scanners (3)
│   ├── dockerfile.ts          # 15 rules
│   ├── kubernetes.ts          # 13 rules
│   └── terraform.ts           # 15 rules
├── remediation/               # Auto-fix
│   ├── code-fixer.ts          # AST-based code transformation
│   └── templates/             # Fix templates
├── reporting/                 # Reporting
│   ├── mermaid-generator.ts   # Diagram generation
│   ├── sarif-generator.ts     # SARIF format
│   └── markdown-formatter.ts
├── external/                  # External APIs
│   ├── cve-lookup.ts          # NVD API integration
│   └── owasp-database.ts      # OWASP Top 10 DB
└── sandbox/                   # Sandbox
    └── docker-manager.ts      # Docker execution management
```

## 🖥️ CLI Mode (CI/CD Integration)

Run the scanner independently without Claude. Works with Jenkins, GitHub Actions, GitLab CI, and any CI/CD platform.

### Basic Usage

```bash
# Scan a file
npx security-scanner-mcp scan ./src/app.js

# Scan a directory
npx security-scanner-mcp scan ./src

# Save results to file
npx security-scanner-mcp scan ./src --output report.txt
```

### Output Formats

```bash
# JSON format (for parsing)
npx security-scanner-mcp scan ./src --format json

# SARIF format (GitHub Code Scanning compatible)
npx security-scanner-mcp scan ./src --format sarif --output report.sarif
```

### CI/CD Options

```bash
# Fail build on critical vulnerabilities (exit code 1)
npx security-scanner-mcp scan ./src --fail-on critical

# Fail build on high or above
npx security-scanner-mcp scan ./src --fail-on high

# Include specific files only
npx security-scanner-mcp scan ./src --include "*.ts,*.js"

# Exclude specific folders
npx security-scanner-mcp scan ./src --exclude "node_modules,dist,test"
```

### Jenkins Example

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npx security-scanner-mcp scan ./src --format json --output security-report.json --fail-on high'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'security-report.json', fingerprint: true
        }
    }
}
```

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        run: npx security-scanner-mcp scan ./src --format sarif --output results.sarif --fail-on critical

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI Example

```yaml
security_scan:
  stage: test
  script:
    - npx security-scanner-mcp scan ./src --format json --output gl-security-report.json --fail-on high
  artifacts:
    reports:
      security: gl-security-report.json
```

## Roadmap

- [x] OWASP Top 10 based scanning
- [x] Multi-language support (JS/TS/Python/Java/Go)
- [x] IaC scanning (Dockerfile, Kubernetes, Terraform)
- [x] Auto-fix suggestions (AST-based)
- [x] Advanced reporting (Mermaid, SARIF)
- [x] External vulnerability DB integration (NVD, OWASP)
- [x] Docker sandbox execution
- [x] CLI mode (CI/CD pipeline integration)
- [ ] GitHub Actions Marketplace
- [ ] VS Code extension

## Contributing

PRs are welcome! We're especially interested in:
- New security pattern additions
- Support for additional languages (Rust, C#, PHP, etc.)
- IaC rule expansion (Ansible, CloudFormation, etc.)
- Documentation improvements

## License

MIT

---

Made with ❤️ by zerry

**Beyond simple scanning, your intelligent security partner.**
