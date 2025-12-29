---
sidebar_position: 3
---

# 자동 수정

탐지된 취약점에 대한 AI 기반 코드 수정 제안을 받으세요.

## 작동 방식

1. **취약점 탐지**: 코드에서 보안 문제 발견
2. **AST 분석**: 코드 구조 이해
3. **수정 생성**: 안전한 대안 제안
4. **검증**: 수정이 동작하는지 확인

## 지원하는 수정 유형

### 비밀 정보

```javascript
// 수정 전
const apiKey = "AIzaSyC1234567890";

// 수정 후
const apiKey = process.env.GOOGLE_API_KEY;
if (!apiKey) {
  throw new Error('GOOGLE_API_KEY environment variable is required');
}
```

### SQL 인젝션

```javascript
// 수정 전
const query = `SELECT * FROM users WHERE id = ${userId}`;

// 수정 후
const query = 'SELECT * FROM users WHERE id = ?';
const results = await db.query(query, [userId]);
```

### XSS

```javascript
// 수정 전
element.innerHTML = userInput;

// 수정 후
element.textContent = userInput;
// 또는 HTML이 필요한 경우
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 암호화

```javascript
// 수정 전
const hash = crypto.createHash('md5').update(password).digest('hex');

// 수정 후
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
```

## 수정 요청 방법

### 기본 요청

```
이 코드의 취약점을 수정해줘:

const password = "admin123";
```

### 설명과 함께

```
보안 모범 사례로 이 코드를 다시 작성해줘:

exec(\`ping \${host}\`);
```

### 단계별 가이드

```
이 SQL 인젝션 문제를 수정하는 방법을 단계별로 설명해줘
```

## 수정 형식

### 코드만

```typescript
// 수정된 코드만 반환
const apiKey = process.env.API_KEY;
```

### 설명 포함

```typescript
// 수정:환경 변수 사용
const apiKey = process.env.API_KEY;

// 이유: API 키를 하드코딩하면 소스 제어에 노출됨
// 권장사항: .env 파일 또는 보안 저장소 사용
```

### 단계별 가이드

1. **환경 변수 설정**: `.env` 파일 생성
2. **dotenv 설치**: `npm install dotenv`
3. **코드 업데이트**: 환경 변수 로드
4. **테스트**: 설정이 작동하는지 확인

## 모범 사례

- ✅ **모든 수정 검토**: 변경 사항을 이해하고 테스트
- ✅ **테스트 작성**: 수정이 동작하는지 확인
- ✅ **점진적 적용**: 한 번에 하나씩 수정
- ❌ **맹목적 적용 금지**: AI는 실수할 수 있음

## 다음 단계

- [코드 스캔](./code-scanning.md) - 취약점 탐지
- [API 참조](../reference/api.md) - 프로그래밍 방식 사용
