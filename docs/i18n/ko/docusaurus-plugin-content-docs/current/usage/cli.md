---
sidebar_position: 2
---

# CLI 사용법

명령줄에서 Security Scanner를 사용하는 방법.

## 기본 명령어

### 코드 스캔

```bash
security-scanner-mcp scan file.js
```

### 디렉토리 스캔

```bash
security-scanner-mcp scan src/
```

### IaC 스캔

```bash
security-scanner-mcp scan-iac Dockerfile
```

## 옵션

```bash
--format json|text|sarif  # 출력 형식
--severity critical|high|medium|low  # 최소 심각도
--output report.json  # 파일로 저장
--verbose  # 상세 출력
```

## 예제

```bash
# JSON으로 출력
security-scanner-mcp scan --format json app.js

# 위험/높음 심각도만
security-scanner-mcp scan --severity high src/

# SARIF 리포트 생성
security-scanner-mcp scan --format sarif --output report.sarif .
```
