# 🔒 Security Scanner MCP

AI가 생성한 코드의 보안 취약점을 자동으로 검출하고, 수정까지 제안하는 **지능형 보안 파트너** MCP 서버입니다.

[![npm version](https://img.shields.io/npm/v/security-scanner-mcp)](https://www.npmjs.com/package/security-scanner-mcp)
[![npm downloads](https://img.shields.io/npm/dm/security-scanner-mcp)](https://www.npmjs.com/package/security-scanner-mcp)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://ongjin.github.io/security-scanner-mcp)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

**[한국어](#korean)** | **[English](README.en.md)** | **[📚 Documentation](https://ongjin.github.io/security-scanner-mcp)**

## Demo

<!-- Add your demo GIF here -->
![Security Scanner Demo](./docs/demo.gif)

## 왜 필요한가요?

AI가 생성한 코드에는 보안 취약점이 **322% 더 많다**는 연구 결과가 있습니다.

이 MCP는 단순 검사를 넘어서:
- 💡 **자동으로 수정 코드를 제안**하고
- 🏗️ **IaC (Dockerfile, Kubernetes, Terraform)까지 검사**하며
- 📊 **Mermaid 다이어그램과 SARIF 리포트를 생성**하고
- 🐳 **Docker 샌드박스에서 안전하게 실행**할 수 있습니다.

코드를 커밋하기 전, 클라우드에 배포하기 전, **한 번만 검사하면 됩니다.**

## ✨ 주요 기능

### 🎯 코드 보안 스캔
| Tool | 설명 |
|------|------|
| `scan-security` | **종합 보안 스캔** - 모든 검사를 한번에 수행 |
| `scan-secrets` | 하드코딩된 API 키, 비밀번호, 토큰 검출 |
| `scan-injection` | SQL/NoSQL/Command Injection 취약점 검사 |
| `scan-xss` | Cross-Site Scripting 취약점 검사 |
| `scan-crypto` | 암호화 취약점 (약한 해시, 불안전한 랜덤 등) |
| `scan-auth` | 인증/세션 취약점 (JWT, 쿠키, CORS 등) |
| `scan-path` | 파일/경로 취약점 (Path Traversal, 업로드 등) |
| `scan-dependencies` | package.json 등에서 취약한 의존성 검사 |

### 🏗️ Infrastructure as Code (IaC) 스캔
| Tool | 설명 |
|------|------|
| `scan-iac` | **Dockerfile, Kubernetes, Terraform** 보안 검사 |

- **Dockerfile**: CIS Docker Benchmark 기반 15개 규칙
- **Kubernetes**: Pod Security Standards (PSS) 기반 13개 규칙
- **Terraform**: AWS/GCP/Azure 보안 설정 15개 규칙

### 🛠️ 자동 수정 & 고급 기능
| Tool | 설명 |
|------|------|
| `get-fix-suggestion` | 취약점에 대한 **수정된 코드 자동 생성** |
| `generate-security-report` | **Mermaid 다이어그램 + SARIF + CVE 정보** 종합 리포트 |
| `scan-in-sandbox` | **Docker 격리 환경**에서 안전하게 스캔 실행 |

## 설치

### npm에서 설치 (권장)

```bash
npm install -g security-scanner-mcp
```

### 또는 소스에서 빌드

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## Claude Code에 등록

```bash
# npm 전역 설치 후
claude mcp add --scope project security-scanner -- security-scanner-mcp

# 또는 소스에서 빌드한 경우
claude mcp add --scope project security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## 빠른 설정 (도구 자동 허용)

매번 도구 사용 승인을 누르는 것이 번거롭다면, 아래 방법으로 자동 허용을 설정하세요.

### 🖥️ Claude Desktop App 사용자
1. Claude 앱을 재시작합니다.
2. `security-scanner` 도구를 사용하는 첫 번째 질문을 던집니다.
3. 알림창이 뜨면 **"Always allow requests from this server"** 체크박스를 클릭하고 **Allow**를 누르세요.
   (이후에는 묻지 않고 실행됩니다.)

### ⌨️ Claude Code (CLI) 사용자
터미널 환경(`claude` 명령어)을 사용 중이라면 권한 관리 명령어를 사용하세요.

1. 터미널에서 `claude`를 실행합니다.
2. 프롬프트 입력창에 `/permissions`를 입력하고 엔터를 칩니다.
3. **Global Permissions** (또는 Project Permissions) > **Allowed Tools**를 선택합니다.
4. `mcp__security-scanner__scan-security`만 입력하거나, 모든 도구를 허용하려면 `mcp__security-scanner__*`를 입력합니다.

> 💡 **Tip**: 대부분의 경우 **`scan-security`** 하나만 허용해도 충분합니다. 이 도구가 모든 보안 검사를 통합해서 수행하기 때문입니다.

## 사용 예시

### 📝 기본 코드 스캔

```
나: 이 코드 보안 검사해줘

const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

Claude: [scan-security 호출]

## ⚠️ 보안 취약점 발견!

### 🔴 Critical (1개)
- **Google API Key** (라인 1)
  - Google API Key가 코드에 하드코딩되어 있습니다
  - 💡 해결책: 환경변수로 관리하고, API 키 제한 설정하기

### 🟠 High (2개)
- **Template Literal SQL** (라인 2)
  - 템플릿 리터럴로 SQL 쿼리에 변수를 삽입하고 있습니다
  - 💡 해결책: Prepared Statement를 사용하세요

- **innerHTML Assignment** (라인 3)
  - innerHTML에 동적 값을 할당하고 있습니다
  - 💡 해결책: textContent를 사용하거나 DOMPurify로 sanitize하세요
```

### 🛠️ 자동 수정 받기

```
나: innerHTML 취약점 수정 코드 보여줘

Claude: [get-fix-suggestion 호출]

## ✅ 수정된 코드

// ❌ Before (취약)
element.innerHTML = userInput;

// ✅ After (안전)
element.textContent = userInput;
// 또는 HTML이 필요한 경우:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 🏗️ IaC 파일 검사

```
나: Dockerfile 보안 검사해줘

Claude: [scan-iac 호출]

## 🐳 Dockerfile 보안 취약점 발견!

### 🔴 Critical (2개)
- **DOC001**: root 사용자로 실행
  - 💡 해결책: USER 명령으로 non-root 사용자 설정

- **DOC005**: 하드코딩된 시크릿
  - 💡 해결책: ARG와 빌드 시크릿 사용

### 🟠 High (3개)
- **DOC002**: latest 태그 사용
  - 💡 해결책: 명시적 버전 태그 사용 (예: node:20-alpine)
...
```

### 📊 종합 리포트 생성

```
나: 전체 보안 리포트를 Mermaid 다이어그램으로 보여줘

Claude: [generate-security-report 호출]

# 🛡️ 보안 스캔 대시보드

## 📊 전체 요약
총 **8개**의 취약점이 발견되었습니다.

## 🎯 심각도별 분포
```mermaid
pie title 심각도별 취약점 분포
    "🔴 Critical" : 2
    "🟠 High" : 3
    "🟡 Medium" : 2
    "🟢 Low" : 1
\```

## ⚔️ 가능한 공격 시나리오
```mermaid
flowchart TD
    Start([공격자]) --> Recon[정찰]
    Recon --> Secrets[하드코딩된<br/>시크릿 발견]
    Secrets --> Access[인증 우회]
    ...
\```

+ SARIF 리포트 (GitHub Code Scanning 호환)
+ CVE/OWASP 상세 정보
```

### 🐳 샌드박스에서 안전하게 실행

```
나: 이 코드를 샌드박스에서 안전하게 검사해줘

Claude: [scan-in-sandbox 호출]

## 🐳 샌드박스 스캔 결과

✅ **스캔 완료**

### 🔒 샌드박스 설정
- **메모리 제한**: 512MB
- **CPU 제한**: 0.5 코어
- **타임아웃**: 30000ms
- **네트워크**: 비활성화
- **권한**: 최소 권한
```

## 검출하는 취약점

### 🔑 하드코딩된 시크릿
- AWS Access Key / Secret Key
- Google API Key / OAuth Secret
- GitHub Token / Slack Token
- Database Connection String
- Private Key (RSA, EC 등)
- JWT Token
- Kakao / Naver API Key
- Stripe / Twilio API Key

### 💉 Injection
- SQL Injection (문자열 연결, 템플릿 리터럴)
- NoSQL Injection (MongoDB)
- Command Injection (exec, spawn)
- LDAP Injection

### 🌐 XSS
- dangerouslySetInnerHTML (React)
- innerHTML / outerHTML
- jQuery .html() / Vue v-html
- eval() / new Function()
- document.write()

### 🔐 암호화
- 약한 해시 (MD5, SHA1)
- 안전하지 않은 랜덤 (Math.random)
- 하드코딩된 암호화 키/IV
- SSL 인증서 검증 비활성화
- 취약한 TLS 버전 (1.0, 1.1)

### 🔒 인증/세션
- JWT 설정 오류 (none 알고리즘, 만료 없음)
- 안전하지 않은 쿠키 설정
- CORS 와일드카드
- 약한 비밀번호 정책

### 📁 파일/경로
- Path Traversal
- 위험한 파일 삭제
- 안전하지 않은 파일 업로드
- Zip Slip (Java)
- Pickle 역직렬화 (Python)

### 🏗️ Infrastructure as Code
**Dockerfile** (CIS Docker Benchmark):
- root 사용자로 실행
- 하드코딩된 시크릿
- latest 태그 사용
- 불필요한 포트 노출
- 헬스체크 누락

**Kubernetes** (Pod Security Standards):
- Privileged 컨테이너
- Root 실행
- Host 네트워크/PID/IPC 사용
- 위험한 Capability 추가
- Resource limit 미설정

**Terraform** (Multi-Cloud):
- 공개 IP 할당
- 암호화 미설정
- 방화벽 전체 오픈 (0.0.0.0/0)
- Public 접근 가능 리소스

### 📦 취약한 의존성
- npm audit 연동
- Python requirements.txt 검사
- Go go.mod 검사

## 지원 언어

- ✅ JavaScript / TypeScript
- ✅ Python
- ✅ Java
- ✅ Go
- ✅ Dockerfile
- ✅ Kubernetes YAML
- ✅ Terraform HCL

## 🎨 리포트 포맷

- **Markdown**: 읽기 쉬운 텍스트 리포트
- **Mermaid**: 시각화 다이어그램 (Pie, Bar, Flowchart)
- **SARIF**: GitHub Code Scanning / VS Code 호환 포맷
- **CVE Enrichment**: NVD 데이터베이스 연동
- **OWASP Mapping**: OWASP Top 10:2021 + CWE 매핑

## 🐳 Docker 샌드박스

악의적인 코드로부터 호스트를 보호하기 위해 Docker 격리 환경에서 스캔을 실행할 수 있습니다.

### Docker 이미지 준비

#### Docker Hub에서 pull (권장)

```bash
# 미리 빌드된 이미지 다운로드 (Trivy, GitLeaks, Checkov 포함)
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

**포함된 외부 보안 도구**:
- Trivy v0.50.4 - 컨테이너/IaC 취약점 스캐너
- GitLeaks v8.18.4 - 시크릿 탐지
- Checkov - Infrastructure as Code 보안 스캐너

#### 소스에서 직접 빌드 (선택사항)

```bash
npm run docker:build
```

> 참고: 빌드에는 5-10분 정도 소요되며, 이미지 크기는 약 500MB입니다.

### 샌드박스에서 스캔 실행

Claude Code에서:
```
scan-in-sandbox 호출
```

**보안 설정**:
- 메모리 제한: 128MB ~ 2GB
- CPU 제한: 0.1 ~ 2.0 코어
- 타임아웃: 5초 ~ 5분
- 네트워크: 기본 비활성화
- 파일시스템: 읽기 전용
- 권한: 최소 권한 (no-new-privileges, drop all capabilities)

## 데모

```bash
# 데모 실행
npm run demo
```

## 아키텍처

```
src/
├── index.ts                    # MCP 서버 (12개 도구)
├── scanners/                   # 코드 스캐너 (8개)
│   ├── secrets.ts
│   ├── injection.ts
│   ├── xss.ts
│   └── ...
├── iac-scanners/              # IaC 스캐너 (3개)
│   ├── dockerfile.ts          # 15개 규칙
│   ├── kubernetes.ts          # 13개 규칙
│   └── terraform.ts           # 15개 규칙
├── remediation/               # 자동 수정
│   ├── code-fixer.ts          # AST 기반 코드 변환
│   └── templates/             # 수정 템플릿
├── reporting/                 # 리포팅
│   ├── mermaid-generator.ts   # 다이어그램 생성
│   ├── sarif-generator.ts     # SARIF 포맷
│   └── markdown-formatter.ts
├── external/                  # 외부 API
│   ├── cve-lookup.ts          # NVD API 연동
│   └── owasp-database.ts      # OWASP Top 10 DB
└── sandbox/                   # 샌드박스
    └── docker-manager.ts      # Docker 실행 관리
```

## 🖥️ CLI 모드 (CI/CD 통합)

Claude 없이 독립적으로 실행할 수 있는 CLI 모드를 제공합니다. Jenkins, GitHub Actions, GitLab CI 등 어디서든 사용 가능합니다.

### 기본 사용법

```bash
# 파일 스캔
npx security-scanner-mcp scan ./src/app.js

# 디렉토리 스캔
npx security-scanner-mcp scan ./src

# 결과를 파일로 저장
npx security-scanner-mcp scan ./src --output report.txt
```

### 출력 포맷

```bash
# JSON 포맷 (파싱용)
npx security-scanner-mcp scan ./src --format json

# SARIF 포맷 (GitHub Code Scanning 호환)
npx security-scanner-mcp scan ./src --format sarif --output report.sarif
```

### CI/CD 옵션

```bash
# Critical 취약점 발견 시 빌드 실패 (exit code 1)
npx security-scanner-mcp scan ./src --fail-on critical

# High 이상 취약점 발견 시 빌드 실패
npx security-scanner-mcp scan ./src --fail-on high

# 특정 파일만 포함
npx security-scanner-mcp scan ./src --include "*.ts,*.js"

# 특정 폴더 제외
npx security-scanner-mcp scan ./src --exclude "node_modules,dist,test"
```

### Jenkins 예시

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

### GitHub Actions 예시

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

### GitLab CI 예시

```yaml
security_scan:
  stage: test
  script:
    - npx security-scanner-mcp scan ./src --format json --output gl-security-report.json --fail-on high
  artifacts:
    reports:
      security: gl-security-report.json
```

## 로드맵

- [x] OWASP Top 10 기반 검사
- [x] 다중 언어 지원 (JS/TS/Python/Java/Go)
- [x] IaC 스캔 (Dockerfile, Kubernetes, Terraform)
- [x] 자동 수정 제안 기능 (AST 기반)
- [x] 고급 리포팅 (Mermaid, SARIF)
- [x] 외부 취약점 DB 연동 (NVD, OWASP)
- [x] Docker 샌드박스 실행
- [x] CLI 모드 (CI/CD 파이프라인 통합)
- [ ] GitHub Actions Marketplace 등록
- [ ] VS Code 확장

## 기여하기

PR 환영합니다! 특히 다음 기여를 기다립니다:
- 새로운 보안 패턴 추가
- 다른 언어 지원 (Rust, C#, PHP 등)
- IaC 규칙 확장 (Ansible, CloudFormation 등)
- 문서 개선

## 라이선스

MIT

---

Made with ❤️ by zerry

**단순 스캐너를 넘어, 지능형 보안 파트너로.**
