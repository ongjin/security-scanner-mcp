---
sidebar_position: 3
---

# MCP 도구

Security Scanner MCP에서 사용 가능한 모든 도구.

## scan-code

코드의 보안 취약점을 스캔합니다.

**파라미터**:
- `code`: 스캔할 소스 코드
- `language`: 프로그래밍 언어

## scan-iac

Infrastructure as Code 파일을 스캔합니다.

**파라미터**:
- `content`: IaC 파일 내용
- `type`: dockerfile | kubernetes | terraform

## scan-in-sandbox

Docker 샌드박스에서 코드를 스캔합니다.

**파라미터**:
- `code`: 스캔할 코드
- `language`: 언어
- `timeout`: 타임아웃 (ms)

## generate-report

종합 보안 리포트를 생성합니다.

**파라미터**:
- `issues`: 보안 이슈 목록
- `format`: markdown | html | sarif

## suggest-fix

탐지된 취약점의 수정 방법을 제안합니다.

**파라미터**:
- `code`: 원본 코드
- `issue`: 보안 이슈
