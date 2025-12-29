---
sidebar_position: 3
---

# CI/CD 통합

개발 워크플로우에 Security Scanner를 통합합니다.

## GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Scanner
        run: npm install -g security-scanner-mcp
      - name: Scan Code
        run: security-scanner-mcp scan --format sarif --output results.sarif src/
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## GitLab CI

```yaml
security_scan:
  image: node:20
  script:
    - npm install -g security-scanner-mcp
    - security-scanner-mcp scan --format json src/
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Pre-commit Hook

```bash
#!/bin/sh
npx security-scanner-mcp scan --severity high .
```

## 다음 단계

- [설정](../reference/configuration.md) - 동작 사용자 정의
- [API](../reference/api.md) - 프로그래밍 방식 사용
