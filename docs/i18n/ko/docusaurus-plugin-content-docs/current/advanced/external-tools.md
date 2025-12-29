---
sidebar_position: 1
---

# 외부 도구

Security Scanner는 향상된 탐지를 위해 업계 표준 보안 도구를 통합합니다.

## Trivy

Aqua Security의 포괄적인 보안 스캐너.

**기능**:
- 컨테이너 이미지 스캔
- IaC 오류 구성
- 비밀 정보 탐지
- 라이선스 스캔

## GitLeaks

엔트로피 분석을 사용한 비밀 정보 탐지.

**기능**:
- 하드코딩된 비밀 정보
- 정규식 패턴
- 엔트로피 기반 탐지
- Git 기록 스캔

## Checkov

Bridgecrew의 IaC 정적 분석 도구.

**기능**:
- Terraform 스캔
- CloudFormation 스캔
- Kubernetes 매니페스트
- 1000개 이상의 정책

## 사용법

외부 도구는 Docker 샌드박스에서 자동으로 사용됩니다:

```
샌드박스에서 이 코드를 스캔해줘
```

## 다음 단계

- [샌드박스](../features/sandbox.md) - Docker 환경
- [리포트](./reporting.md) - 결과 형식
