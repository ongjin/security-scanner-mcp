---
sidebar_position: 4
---

# Docker 샌드박스 스캔

최대한의 안전을 위해 격리된 Docker 환경에서 보안 스캔을 실행합니다.

## 샌드박스를 사용하는 이유?

잠재적으로 악성인 코드로부터 호스트 시스템을 보호:
- ✅ **격리된 실행** - 컨테이너 환경에서 코드 실행
- ✅ **리소스 제한** - CPU, 메모리, 시간 제약
- ✅ **네트워크 격리** - 외부 네트워크 액세스 없음
- ✅ **읽기 전용 파일시스템** - 호스트 파일 수정 불가
- ✅ **향상된 스캔** - 외부 도구 사용 (Trivy, Checkov, GitLeaks)

## 설정

### Docker Hub에서 가져오기 (권장)

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

### 또는 소스에서 빌드

```bash
npm run docker:build
```

## 사용법

### 기본 샌드박스 스캔

```
샌드박스에서 이 코드를 스캔해줘

const apiKey = "AIzaSyC1234567890abcdef";
const query = \`SELECT * FROM users WHERE id = \${userId}\`;
```

Claude가 `scan-in-sandbox`를 호출하여:
1. 코드를 임시 파일에 작성
2. Docker 컨테이너 실행
3. 컨테이너 내부에서 모든 스캐너 실행
4. JSON 결과 반환
5. 컨테이너 정리

## 보안 구성

### 기본 설정

```
메모리 제한: 512MB
CPU 제한: 0.5 코어
타임아웃: 30초
네트워크: 비활성화
파일시스템: 읽기 전용 (/tmp 제외)
권한: 제거됨 (no-new-privileges)
```

### 사용자 정의 옵션

```bash
SANDBOX_MEMORY=1g \
SANDBOX_CPU=1.0 \
SANDBOX_TIMEOUT=60000 \
scan-in-sandbox
```

## 샌드박스에서 사용 가능한 스캐너

### 내장 스캐너
- 비밀 정보 탐지
- SQL/NoSQL/커맨드 인젝션
- XSS 취약점

### 외부 도구 (Docker만 해당)
- **GitLeaks**: 엔트로피 분석을 통한 향상된 비밀 정보 탐지
- **Trivy**: IaC 및 컨테이너 취약점 스캔
- **Checkov**: Infrastructure as Code 보안 분석

## 다음 단계

- [외부 도구](../advanced/external-tools.md) - Trivy, Checkov, GitLeaks에 대해 배우기
- [리포트](../advanced/reporting.md) - SARIF 리포트 생성
