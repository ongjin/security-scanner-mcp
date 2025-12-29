---
sidebar_position: 2
---

# IaC 스캔

Infrastructure as Code 파일의 보안 잘못된 구성을 탐지합니다.

## 지원 형식

### Dockerfile

**탐지 항목**:
- 🔴 최신 태그 사용
- 🔴 Root 사용자로 실행
- 🟠 하드코딩된 비밀 정보
- 🟡 불필요한 권한

**예제**:
```dockerfile
# ❌ 안전하지 않음
FROM ubuntu:latest
ENV API_KEY="secret123"
USER root

# ✅ 안전함
FROM ubuntu:22.04
ENV API_KEY=""
RUN adduser --disabled-password scanner
USER scanner
```

### Kubernetes

**탐지 항목**:
- 🔴 특권 모드
- 🔴 hostPath 마운트
- 🟠 보안 컨텍스트 누락
- 🟡 리소스 제한 없음

**예제**:
```yaml
# ❌ 안전하지 않음
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true

# ✅ 안전함
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
```

### Terraform

**탐지 항목**:
- 🔴 공개 S3 버킷
- 🔴 과도한 IAM 권한
- 🟠 암호화되지 않은 리소스
- 🟡 보안 그룹 규칙

**예제**:
```hcl
# ❌ 안전하지 않음
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}

# ✅ 안전함
resource "aws_s3__bucket" "data" {
  bucket = "my-bucket"
  acl    = "private"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

## 다음 단계

- [외부 도구](../advanced/external-tools.md) - Trivy, Checkov
- [리포트](../advanced/reporting.md) - SARIF 형식
