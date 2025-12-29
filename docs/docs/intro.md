---
sidebar_position: 1
---

# Introduction

Welcome to **Security Scanner MCP** documentation!

## What is Security Scanner MCP?

Security Scanner MCP is your **intelligent security partner** that automatically detects vulnerabilities in AI-generated code and suggests fixes.

Research shows that AI-generated code contains **322% more security vulnerabilities** than human-written code. This MCP server goes beyond simple scanning to help you write secure code.

## Why do you need this?

AI code generation tools are powerful, but they often produce code with security vulnerabilities. Security Scanner MCP helps you:

- 💡 **Auto-generate fix suggestions** for detected vulnerabilities
- 🏗️ **Scan IaC files** (Dockerfile, Kubernetes, Terraform)
- 📊 **Create visual reports** with Mermaid diagrams and SARIF format
- 🐳 **Run safely in Docker sandbox** for isolation
- 🔍 **Use industry-standard tools** (Trivy, Checkov, GitLeaks)

## Key Features

### Code Security Scanning

- Hardcoded secrets detection (API keys, passwords, tokens)
- SQL/NoSQL/Command injection vulnerabilities
- Cross-Site Scripting (XSS) risks
- Cryptographic weaknesses
- Authentication and session security issues
- File and path vulnerabilities
- Vulnerable dependencies

### Infrastructure as Code (IaC) Scanning

- **Dockerfile**: 15+ rules based on CIS Docker Benchmark
- **Kubernetes**: 13+ rules based on Pod Security Standards
- **Terraform**: 15+ rules for AWS/GCP/Azure security

### Advanced Features

- **Auto-fix suggestions**: AST-based code transformation
- **Comprehensive reports**: Mermaid diagrams + SARIF + CVE info
- **Docker sandbox**: Isolated scanning environment
- **External tools**: Trivy, Checkov, GitLeaks integration

## Quick Example

```typescript
// ❌ Vulnerable code
const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

// Claude detects:
// 🔴 Critical: Google API Key hardcoded
// 🟠 High: SQL Injection via template literal
// 🟠 High: XSS via innerHTML assignment
```

## Next Steps

- [Installation](./installation.md) - Install Security Scanner MCP
- [Quick Start](./quick-start.md) - Get started in 5 minutes
- [Usage Guide](./usage/basic-usage.md) - Learn how to use all features
