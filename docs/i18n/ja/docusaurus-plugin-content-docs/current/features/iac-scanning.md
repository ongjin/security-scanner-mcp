---
sidebar_position: 2
---

# インフラストラクチャ・アズ・コード（IaC）スキャン

インフラストラクチャ設定ファイルのセキュリティの問題をスキャンします。

## サポートされているIaC形式

### 🐳 Dockerfile

**CIS Dockerベンチマークに基づく15以上のルール**

一般的に検出される問題:
- コンテナがrootで実行
- ENV や ARG にハードコードされたシークレット
- `latest`タグを使用
- 不要なポート公開
- ヘルスチェック欠落
- `apt-get update`の後にクリーンアップなし
- `ADD`の代わりに`COPY`を使用していない
- `USER`命令なし

**例:**

```dockerfile
# ❌ 脆弱
FROM node:latest
ENV API_KEY="secret123"
RUN apt-get update && apt-get install -y curl
EXPOSE 22
# USER命令なし - rootで実行

# ✅ 安全
FROM node:20-alpine
ARG API_KEY
RUN apk add --no-cache curl && \
    rm -rf /var/cache/apk/*
EXPOSE 3000
USER node
HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1
```

### ☸️ Kubernetes

**ポッドセキュリティ標準に基づく13以上のルール**

一般的に検出される問題:
- 特権コンテナ
- rootで実行
- ホストネットワーク/PID/IPC使用
- 危険な機能追加（SYS_ADMIN、NET_ADMIN）
- リソースリミットなし
- ルートファイルシステムが読み取り・書き込み可能
- 特権昇格が許可
- ホストパスマウント

**例:**

```yaml
# ❌ 脆弱
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
    resources: {}

# ✅ 安全
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:1.2.3
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
```

### 🏗️ Terraform

**AWS/GCP/Azure向けの15以上のルール**

一般的に検出される問題:
- 機密リソースへの公開IP割り当て
- ストレージ/データベースの暗号化無効
- 0.0.0.0/0に開かれたセキュリティグループ
- 公開アクセス可能なS3バケット
- VPCフロー ログなし
- EBSボリュームの暗号化なし
- ワイルドカード付きIAMポリシー
- 重要な操作にMFAなし

**例:**

```hcl
# ❌ 脆弱
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ 安全
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # 内部のみ
  }
}
```

## 使用方法

### 基本的なIaCスキャン

```
Me: このDockerfileをセキュリティの問題についてスキャンしてください

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update && apt-get install curl
```

### Kubernetes YAMLをスキャン

```
Me: このKubernetesマニフェストをセキュリティの問題についてチェックしてください

[YAMLを貼り付け]
```

### Terraform設定をスキャン

```
Me: このTerraformファイルをセキュリティミスコンフィグレーションについてレビューしてください

[.tfファイルを貼り付け]
```

## 外部ツール統合

Docker サンドボックス（`scan-in-sandbox`）を使用する場合、追加の業界標準ツールが使用されます:

### Trivy
- **バージョン**: 0.50.4
- **目的**: コンテナとIaC脆弱性スキャナー
- 包括的なミスコンフィグレーション検出
- CVEデータベース統合

### Checkov
- **目的**: IaCセキュリティスキャナー
- 1000以上の組み込みポリシー
- コンプライアンスフレームワーク（CIS、PCI-DSS、HIPAA）
- マルチクラウド対応

## スキャン結果

結果に含まれるもの:
- **ルールID**: 特定のミスコンフィグレーション識別子
- **重大度**: Critical、High、Medium、Low
- **説明**: 問題の内容
- **修正**: 対処方法
- **OWASPカテゴリ**: OWASP Top 10へのマッピング
- **CWE ID**: Common Weakness Enumeration

## ベストプラクティス

1. **早期にスキャン**: CI/CDパイプラインに含める
2. **特定のバージョンを使用**: `latest`タグを避ける
3. **最小権限の原則に従う**: 最小限の権限
4. **暗号化を有効化**: 保存中のデータと転送中のデータ
5. **定期的に更新**: ベースイメージと依存関係を最新に

## 次のステップ

- [自動修正](./auto-fix.md) - 自動修復提案を取得
- [サンドボックススキャン](./sandbox.md) - Docker隔離環境で実行
- [外部ツール](../advanced/external-tools.md) - TrivyとCheckovについて学ぶ
