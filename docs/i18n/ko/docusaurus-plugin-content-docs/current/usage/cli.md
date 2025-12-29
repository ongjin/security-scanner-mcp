---
sidebar_position: 2
---

# CLI 모드

Claude 없이 독립적으로 Security Scanner MCP를 실행할 수 있습니다. Jenkins, GitHub Actions, GitLab CI 등 모든 CI/CD 파이프라인에서 사용 가능합니다.

## 설치

```bash
# 전역 설치
npm install -g security-scanner-mcp

# 또는 npx 사용 (설치 필요 없음)
npx security-scanner-mcp scan ./src
```

## 명령어

### scan

파일 또는 디렉토리의 보안 취약점을 스캔합니다.

```bash
# 단일 파일 스캔
security-scanner-mcp scan ./src/app.js

# 디렉토리 스캔
security-scanner-mcp scan ./src

# 언어 지정
security-scanner-mcp scan ./src --language typescript
```

### serve

MCP 서버 모드로 실행합니다 (Claude Desktop/Code와 함께 사용).

```bash
security-scanner-mcp serve
```

## 출력 포맷

### Text (기본값)

사람이 읽기 쉬운 컬러 출력입니다.

```bash
security-scanner-mcp scan ./src
```

출력 예시:
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

자동화 및 파싱을 위한 기계 판독 가능 형식입니다.

```bash
security-scanner-mcp scan ./src --format json
```

출력 구조:
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
      "message": "API 키가 코드에 하드코딩되어 있습니다",
      "fix": "환경변수를 사용하세요",
      "owaspCategory": "A07:2021",
      "cweId": "CWE-798"
    }
  ]
}
```

### SARIF

GitHub Code Scanning 호환 형식입니다.

```bash
security-scanner-mcp scan ./src --format sarif --output report.sarif
```

## CLI 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-f, --format <format>` | 출력 형식 (text, json, sarif) | text |
| `-o, --output <file>` | 결과를 파일로 저장 | - |
| `-l, --language <lang>` | 프로그래밍 언어 | auto |
| `-s, --severity <level>` | 최소 심각도 필터 | low |
| `--fail-on <level>` | 해당 레벨 이상 발견 시 exit code 1 | critical |
| `--include <patterns>` | 포함할 파일 패턴 | *.js,*.ts,*.py,*.java,*.go |
| `--exclude <patterns>` | 제외할 패턴 | node_modules,dist,build,.git |
| `--no-color` | 컬러 출력 비활성화 | - |

### 언어 옵션

- `auto` - 파일 확장자 기반 자동 감지
- `javascript` - JavaScript 파일
- `typescript` - TypeScript 파일
- `python` - Python 파일
- `java` - Java 파일
- `go` - Go 파일

### 심각도 레벨

- `critical` - 가장 심각한 취약점
- `high` - 높은 심각도
- `medium` - 중간 심각도
- `low` - 낮은 심각도 (정보성)

## CI/CD 통합

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
            echo '보안 취약점이 발견되었습니다!'
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

## Exit 코드

| 코드 | 설명 |
|------|------|
| 0 | 성공 - `--fail-on` 레벨 이상의 이슈 없음 |
| 1 | 실패 - `--fail-on` 레벨 이상의 이슈 발견 |

## 사용 예시

### TypeScript 파일만 스캔

```bash
security-scanner-mcp scan ./src --include "*.ts,*.tsx"
```

### 테스트 파일 제외

```bash
security-scanner-mcp scan ./src --exclude "*.test.ts,*.spec.ts,__tests__"
```

### High 이상만 표시

```bash
security-scanner-mcp scan ./src --severity high
```

### High 이상 발견 시 빌드 실패

```bash
security-scanner-mcp scan ./src --fail-on high
```

### 코드 리뷰용 리포트 생성

```bash
security-scanner-mcp scan ./src --format json --output pr-security-report.json
```

## Pre-commit 훅

### Husky 사용

```bash
# Husky 설치
npm install --save-dev husky

# Husky 초기화
npx husky init

# Pre-commit 훅 추가
echo 'npx security-scanner-mcp scan ./src --fail-on high' > .husky/pre-commit
```

### lint-staged 사용

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

## Docker 사용

```bash
# 이미지 다운로드
docker pull ongjin/security-scanner-mcp:latest

# 로컬 파일 스캔
docker run --rm \
  -v $(pwd):/code:ro \
  ongjin/security-scanner-mcp:latest \
  scan /code/src --format json
```

## 다음 단계

- [MCP 도구](./mcp-tools.md) - MCP 서버 도구 알아보기
- [통합](../advanced/integration.md) - 고급 CI/CD 통합
- [설정](../reference/configuration.md) - 상세 설정 옵션
