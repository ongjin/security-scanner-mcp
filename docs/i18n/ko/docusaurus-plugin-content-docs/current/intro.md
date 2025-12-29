---
sidebar_position: 1
---

# 소개

**Security Scanner MCP** 문서에 오신 것을 환영합니다!

## Security Scanner MCP란?

Security Scanner MCP는 AI가 생성한 코드의 취약점을 자동으로 탐지하고 수정 방법을 제안하는 **지능형 보안 파트너**입니다.

연구에 따르면 AI가 생성한 코드는 사람이 작성한 코드보다 **322% 더 많은 보안 취약점**을 포함하고 있습니다. 이 MCP 서버는 단순한 스캐닝을 넘어 안전한 코드 작성을 도와줍니다.

## 왜 필요한가요?

AI 코드 생성 도구는 강력하지만, 보안 취약점이 있는 코드를 생성하는 경우가 많습니다. Security Scanner MCP는 다음을 도와줍니다:

- 💡 **자동 수정 제안** - 발견된 취약점에 대한 수정 코드 생성
- 🏗️ **IaC 파일 스캔** - Dockerfile, Kubernetes, Terraform 분석
- 📊 **시각적 리포트** - Mermaid 다이어그램과 SARIF 형식 리포트
- 🐳 **Docker 샌드박스** - 격리된 환경에서 안전하게 실행
- 🔍 **산업 표준 도구** - Trivy, Checkov, GitLeaks 통합

## 주요 기능

### 코드 보안 스캔

- 하드코딩된 시크릿 탐지 (API 키, 비밀번호, 토큰)
- SQL/NoSQL/Command Injection 취약점
- Cross-Site Scripting (XSS) 위험
- 암호화 약점
- 인증 및 세션 보안 문제
- 파일 및 경로 취약점
- 취약한 의존성

### Infrastructure as Code (IaC) 스캔

- **Dockerfile**: CIS Docker Benchmark 기반 15+ 규칙
- **Kubernetes**: Pod Security Standards 기반 13+ 규칙
- **Terraform**: AWS/GCP/Azure 보안을 위한 15+ 규칙

### 고급 기능

- **자동 수정 제안**: AST 기반 코드 변환
- **종합 리포트**: Mermaid 다이어그램 + SARIF + CVE 정보
- **Docker 샌드박스**: 격리된 스캔 환경
- **외부 도구 통합**: Trivy, Checkov, GitLeaks

## 간단한 예제

```typescript
// ❌ 취약한 코드
const apiKey = "AIzaSyC1234567890abcdef";
const query = `SELECT * FROM users WHERE id = ${userId}`;
element.innerHTML = userInput;

// Claude가 탐지:
// 🔴 Critical: Google API Key 하드코딩
// 🟠 High: 템플릿 리터럴을 통한 SQL Injection
// 🟠 High: innerHTML을 통한 XSS
```

## 다음 단계

- [설치](./installation.md) - Security Scanner MCP 설치하기
- [빠른 시작](./quick-start.md) - 5분 안에 시작하기
- [사용 가이드](./usage/basic-usage.md) - 모든 기능 사용법 배우기
