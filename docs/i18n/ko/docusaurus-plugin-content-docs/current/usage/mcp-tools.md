---
sidebar_position: 3
---

# MCP 도구

Security Scanner MCP에서 사용 가능한 모든 도구.

## 1.2.0 탐지 동작

JavaScript / TypeScript 코드 스캔은 AST 기반으로 동작합니다. `scan-security`, `scan-injection`, `scan-xss`, `scan-crypto`, `scan-auth`, `scan-path`는 함수 파라미터 taint, 다단계 변수 흐름, `setHeader` CORS 와일드카드, 동적 `innerHTML` 할당을 더 정확하게 탐지합니다. Python / Java / Go는 regex 경로를 유지합니다.

## 핵심 스캔 도구

### scan-security

모든 코드 스캐너를 한 번에 실행하는 종합 보안 스캔입니다.

**실행 항목**:
- `scan-secrets`
- `scan-injection`
- `scan-xss`
- `scan-crypto`
- `scan-auth`
- `scan-path`
- `scan-dependencies`

### scan-secrets

하드코딩된 API 키, 비밀번호, 토큰, private key를 탐지합니다.

### scan-injection

SQL/NoSQL/Command Injection을 탐지합니다. JavaScript / TypeScript에서는 함수 파라미터 taint와 다단계 변수 흐름도 추적합니다.

### scan-xss

`dangerouslySetInnerHTML`, 동적 `innerHTML` / `outerHTML`, jQuery `.html()`, Vue `v-html`, `eval()` / `new Function()` 사용을 탐지합니다. 정적 리터럴 HTML은 XSS로 보고하지 않습니다.

### scan-crypto

약한 해시, 안전하지 않은 난수, 하드코딩된 암호화 키, 다단계 taint가 들어간 평문 비밀번호 저장을 탐지합니다.

### scan-auth

JWT 설정 오류, 안전하지 않은 쿠키, CORS 와일드카드(`setHeader` / `header` 포함), 약한 비밀번호 정책을 탐지합니다.

### scan-path

Path Traversal, 위험한 파일 작업, 안전하지 않은 업로드, Zip Slip, Pickle 역직렬화를 탐지합니다. JavaScript / TypeScript에서는 다단계 파일 경로 흐름도 추적합니다.

### scan-dependencies

`package.json`, `requirements.txt`, `go.mod`의 취약한 의존성을 검사합니다.

## scan-iac

Dockerfile, Kubernetes YAML, Terraform HCL 같은 Infrastructure as Code 파일을 스캔합니다.

**파라미터**:
- `content`: IaC 파일 내용
- `type`: dockerfile | kubernetes | terraform

## scan-in-sandbox

Docker 샌드박스에서 코드를 격리 실행하며 스캔합니다.

**파라미터**:
- `code`: 스캔할 코드
- `language`: 언어
- `timeout`: 타임아웃 (ms)

## generate-security-report

종합 보안 리포트를 생성합니다.

**파라미터**:
- `issues`: 보안 이슈 목록
- `format`: markdown | sarif

## get-fix-suggestion

탐지된 취약점의 수정 방법을 제안합니다.

**파라미터**:
- `code`: 원본 코드
- `issue`: 보안 이슈
