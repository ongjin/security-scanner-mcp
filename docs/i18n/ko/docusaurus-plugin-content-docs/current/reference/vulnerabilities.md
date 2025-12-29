---
sidebar_position: 1
---

# 취약점 참조

Security Scanner MCP가 탐지하는 모든 취약점 유형에 대한 완전한 참조.

## OWASP Top 10:2021 매핑

### A01:2021 - 손상된 접근 제어

**탐지 항목**:
- 인증 검사 누락
- 안전하지 않은 직접 객체 참조
- 경로 탐색 취약점

### A02:2021 - 암호화 실패

**탐지 항목**:
- 약한 해싱 알고리즘 (MD5, SHA1)
- 하드코딩된 암호화 키
- 안전하지 않은 난수 생성

### A03:2021 - 인젝션

**탐지 항목**:
- SQL 인젝션
- NoSQL 인젝션
- 커맨드 인젝션

### A07:2021 - 식별 및 인증 실패

**탐지 항목**:
- 하드코딩된 자격 증명
- 약한 비밀번호 정책
- 안전하지 않은 세션 관리

## CWE 매핑

### CWE-78: OS 커맨드 인젝션

```javascript
// 취약함
child_process.exec(\`git clone \${repo_url}\`);

// 안전함
child_process.execFile('git', ['clone', repo_url]);
```

### CWE-79: 크로스 사이트 스크립팅 (XSS)

```javascript
// 취약함
element.innerHTML = userInput;

// 안전함
element.textContent = userInput;
```

### CWE-89: SQL 인젝션

```javascript
// 취약함
db.query(\`SELECT * FROM users WHERE id = \${id}\`);

// 안전함
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

## 심각도 정의

### 🔴 위험 (CVSS 9.0-10.0)

즉각적인 조치 필요:
- 원격 코드 실행
- 인증 우회
- 노출된 자격 증명

**대응 시간**: 즉시 수정 (< 24시간)

### 🟠 높음 (CVSS 7.0-8.9)

긴급 조치 필요:
- SQL/NoSQL 인젝션
- XSS 취약점
- 권한 상승

**대응 시간**: 1주일 이내 수정

### 🟡 보통 (CVSS 4.0-6.9)

해결 권장:
- 정보 노출
- 약한 암호화
- 보안 헤더 누락

**대응 시간**: 1개월 이내 수정

### 🟢 낮음 (CVSS 0.1-3.9)

권장 수정:
- 모범 사례 위반
- 심층 방어 개선

**대응 시간**: 다음 릴리스에서 수정

## 다음 단계

- [설정](./configuration.md) - 탐지 규칙 사용자 정의
- [API 참조](./api.md) - 프로그래밍 방식 사용
