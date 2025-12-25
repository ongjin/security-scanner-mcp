# 🔒 Security Scanner MCP

AI가 생성한 코드의 보안 취약점을 자동으로 검출하는 MCP 서버입니다.

![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

## 왜 필요한가요?

AI가 생성한 코드에는 보안 취약점이 **322% 더 많다**는 연구 결과가 있습니다. 이 MCP는 코드를 커밋하기 전에 자동으로 보안 검사를 수행합니다.

## 기능

| Tool | 설명 |
|------|------|
| `scan-security` | **종합 보안 스캔** (모든 검사를 한번에) |
| `scan-secrets` | 하드코딩된 API 키, 비밀번호, 토큰 검출 |
| `scan-injection` | SQL Injection, Command Injection 취약점 검사 |
| `scan-xss` | Cross-Site Scripting 취약점 검사 |
| `scan-crypto` | 암호화 취약점 (약한 해시, 안전하지 않은 랜덤 등) |
| `scan-auth` | 인증/세션 취약점 (JWT, 쿠키, CORS 등) |
| `scan-path` | 파일/경로 취약점 (Path Traversal, 업로드 등) |
| `scan-dependencies` | package.json 등에서 취약한 의존성 검사 |

## 설치

### npm에서 설치 (권장)

```bash
npm install -g security-scanner-mcp
```

### 또는 소스에서 빌드

```bash
git clone https://github.com/zerry/security-scanner-mcp.git
cd security-scanner-mcp
npm install && npm run build
```

## Claude Code에 등록

```bash
# npm 전역 설치 후
claude mcp add security-scanner -- security-scanner-mcp

# 또는 소스에서 빌드한 경우
claude mcp add security-scanner -- node /path/to/security-scanner-mcp/dist/index.js
```

## 사용 예시

Claude Code에서:

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

## 검출하는 취약점

### 🔑 하드코딩된 시크릿
- AWS Access Key / Secret Key
- Google API Key / OAuth Secret
- GitHub Token / Slack Token
- Database Connection String
- Private Key (RSA, EC 등)
- JWT Token
- Kakao / Naver API Key

### 💉 Injection
- SQL Injection (문자열 연결, 템플릿 리터럴)
- NoSQL Injection (MongoDB)
- Command Injection (exec, spawn)

### 🌐 XSS
- dangerouslySetInnerHTML (React)
- innerHTML / outerHTML
- jQuery .html() / Vue v-html
- eval() / new Function()

### 🔐 암호화
- 약한 해시 (MD5, SHA1)
- 안전하지 않은 랜덤 (Math.random)
- 하드코딩된 암호화 키/IV
- SSL 인증서 검증 비활성화

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

### 📦 취약한 의존성
- npm audit 연동
- Python requirements.txt 검사
- Go go.mod 검사

## 지원 언어

- ✅ JavaScript / TypeScript
- ✅ Python
- ✅ Java (Spring Boot 포함!)
- ✅ Go

## 데모

```bash
# 데모 실행
npm run demo
```

## 로드맵

- [x] OWASP Top 10 기반 검사
- [x] 다중 언어 지원
- [ ] 외부 취약점 DB 연동 (NVD, OSV)
- [ ] 자동 수정 제안 기능
- [ ] GitHub Actions 연동
- [ ] VS Code 확장

## 기여하기

PR 환영합니다! 특히 다음 기여를 기다립니다:
- 새로운 보안 패턴 추가
- 다른 언어 지원
- 문서 개선

## 라이선스

MIT

---

Made with ❤️ by zerry
