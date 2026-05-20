---
sidebar_position: 3
---

# 빠른 시작

5분 안에 Security Scanner MCP를 시작하고 첫 보안 스캔을 실행하세요.

## 1단계: 설치 확인

Security Scanner MCP가 설치되어 있는지 확인:

```bash
security-scanner-mcp --version
```

설치되지 않았다면 [설치 가이드](./installation.md)를 참조하세요.

## 2단계: 첫 스캔

### Claude Desktop 사용

Claude Desktop을 열고 다음과 같이 입력하세요:

```
이 코드를 스캔해줘:

const apiKey = "AIzaSyC1234567890abcdef";
const password = "admin123";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claude가 자동으로 `scan-security` MCP 도구를 호출하고 다음을 보고합니다:
- 🔴 **위험**: Google API 키 하드코딩
- 🔴 **위험**: 비밀번호 하드코딩
- 🟠 **높음**: SQL 인젝션 취약점

### 1.2.0 AST 기반 탐지 예시

```javascript
function findUser(input) {
  db.query(`SELECT * FROM users WHERE id = ${input}`);
}
findUser(req.body.userId);
```

JavaScript / TypeScript는 AST 기반 탐지를 사용하므로 함수 파라미터와 다단계 변수 흐름도 탐지됩니다. `el.innerHTML = '<div>safe</div>'`처럼 리터럴 HTML만 넣는 코드는 XSS로 보고하지 않습니다.

### CLI 사용

```bash
echo 'const apiKey = "sk_test_1234";' | security-scanner-mcp scan
```

## 3단계: IaC 스캔

Dockerfile을 스캔해보세요:

```
이 Dockerfile을 스캔해줘:

FROM ubuntu:latest
RUN apt-get update
ENV SECRET_KEY="hardcoded_secret"
USER root
```

Claude가 다음을 탐지합니다:
- 🟠 **높음**: 최신 태그 사용
- 🔴 **위험**: 하드코딩된 비밀 정보
- 🟠 **높음**: root 사용자로 실행

## 4단계: 자동 수정 받기

```
이전 코드에 대한 수정 방법을 제안해줘
```

Claude가 다음을 제공합니다:
- ✅ 보안 코드 예제
- 📝 단계별 수정 가이드
- 💡 모범 사례 권장사항

## 일반적인 사용 예

### 비밀 정보 탐지

```javascript
// ❌ 탐지됨
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY = "sk_live_1234567890";

// ✅ 권장
const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;
```

### SQL 인젝션

```javascript
// ❌ 취약함
const query = `SELECT * FROM users WHERE email = '${userEmail}'`;

// ✅ 안전함
const query = 'SELECT * FROM users WHERE email = ?';
db.execute(query, [userEmail]);
```

### XSS 방지

```javascript
// ❌ 위험함
element.innerHTML = userInput;

// ✅ 안전함
element.textContent = userInput;
```

## 고급 기능 사용

### 샌드박스 스캔

신뢰할 수 없는 코드의 경우:

```
샌드박스에서 이 코드를 스캔해줘:

[잠재적으로 악성인 코드]
```

### 포괄적인 리포트 생성

```
전체 보안 리포트를 Mermaid 다이어그램과 함께 생성해줘
```

### SARIF 내보내기

```
결과를 SARIF 형식으로 내보내줘
```

## 다음 단계

### 모든 기능 알아보기

- [코드 스캔](./features/code-scanning.md) - 심층 코드 분석
- [IaC 스캔](./features/iac-scanning.md) - 인프라 보안
- [자동 수정](./features/auto-fix.md) - 자동 코드 수정
- [샌드박스](./features/sandbox.md) - 격리된 스캔

### 워크플로우에 통합

- [CLI 사용법](./usage/cli.md) - 명령줄 옵션
- [MCP 도구](./usage/mcp-tools.md) - 사용 가능한 모든 도구
- [CI/CD 통합](./advanced/integration.md) - 파이프라인에 추가

## 도움이 필요하세요?

- 📚 [전체 문서 찾아보기](./intro.md)
- 🐛 [문제 보고](https://github.com/ongjin/security-scanner-mcp/issues)
- 💬 [토론 참여](https://github.com/ongjin/security-scanner-mcp/discussions)
