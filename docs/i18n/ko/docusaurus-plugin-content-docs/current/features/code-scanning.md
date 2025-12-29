---
sidebar_position: 1
---

# 코드 스캔

AI가 생성한 코드의 보안 취약점을 자동으로 탐지합니다.

## 지원하는 취약점 유형

### 1. 비밀 정보 탐지

하드코딩된 API 키, 비밀번호 및 토큰을 탐지합니다.

**탐지 패턴**:
- AWS 액세스 키
- Google API 키
- GitHub 토큰
- Slack 토큰
- 프라이빗 키
- 데이터베이스 비밀번호

**예제**:
```javascript
// ❌ 탐지됨: Google API 키
const API_KEY = "AIzaSyC1234567890abcdef";

// ✅ 권장사항
const API_KEY = process.env.GOOGLE_API_KEY;
```

### 2. 인젝션 취약점

SQL, NoSQL, 커맨드 인젝션 공격을 탐지합니다.

**SQL 인젝션**:
```javascript
// ❌ 취약함
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// ✅ 안전함
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);
```

**커맨드 인젝션**:
```javascript
// ❌ 위험함
exec(`ping ${userHost}`);

// ✅ 안전함
execFile('ping', [userHost]);
```

### 3. XSS (크로스 사이트 스크립팅)

DOM 기반 및 반사 XSS 취약점을 탐지합니다.

```javascript
// ❌ 위험함
element.innerHTML = userInput;
document.write(data);
eval(code);

// ✅ 안전함
element.textContent = userInput;
// document.write 대신 DOM API 사용
// eval 사용 금지
```

### 4. 암호화 약점

약한 암호화 알고리즘과 안전하지 않은 랜덤 생성을 탐지합니다.

```javascript
// ❌ 약함
const hash = crypto.createHash('md5');
const random = Math.random();

// ✅ 강함
const hash = crypto.createHash('sha256');
const random = crypto.randomBytes(32);
```

### 5. 인증 및 세션 보안

안전하지 않은 세션 처리와 약한 인증을 탐지합니다.

```javascript
// ❌ 안전하지 않음
res.cookie('session', token);

// ✅ 안전함
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

### 6. 경로 탐색

파일 경로 탐색 및 디렉토리 트래버설 공격을 탐지합니다.

```javascript
// ❌ 취약함
const file = fs.readFileSync(userPath);

// ✅ 안전함
const safePath = path.resolve(basePath, path.normalize(userPath));
if (!safePath.startsWith(basePath)) {
  throw new Error('Invalid path');
}
const file = fs.readFileSync(safePath);
```

## 탐지 방법

### 정적 분석

- **패턴 매칭**: 정규식 기반 탐지
- **AST 분석**: 추상 구문 트리 파싱
- **데이터 흐름**: 변수 추적

### 심각도 수준

- 🔴 **위험** (CVSS 9.0-10.0): 즉시 수정 필요
- 🟠 **높음** (CVSS 7.0-8.9): 긴급 조치 필요
- 🟡 **보통** (CVSS 4.0-6.9): 해결 권장
- 🟢 **낮음** (CVSS 0.1-3.9): 모범 사례 개선

## 지원 언어

- **JavaScript/TypeScript**: 전체 지원
- **Python**: 주요 취약점
- **Java**: 인젝션 및 암호화
- **Go**: 보안 모범 사례
- **기타**: 일반 패턴

## 사용 예제

### 기본 스캔

```
이 코드를 스캔해줘:

const password = "admin123";
const query = \`SELECT * FROM users WHERE name = \${userName}\`;
```

### 특정 취약점 유형

```
SQL 인젝션만 확인해줘:

const sql = "DELETE FROM " + tableName;
```

### 파일 스캔

```
src/auth.js 파일을 스캔해줘
```

## 다음 단계

- [IaC 스캔](./iac-scanning.md) - 인프라 보안
- [자동 수정](./auto-fix.md) - 수정 제안
- [취약점 참조](../reference/vulnerabilities.md) - 전체 목록
