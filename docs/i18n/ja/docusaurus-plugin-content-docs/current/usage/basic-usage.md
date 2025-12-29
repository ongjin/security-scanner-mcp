---
sidebar_position: 1
---

# 基本的な使用方法

Security Scanner MCPを Claudeで使用する方法を学びます。

## クイックスキャン

コードをスキャンする最も簡単な方法:

```
Me: このコードをセキュリティの問題についてスキャンしてください

const apiKey = "sk_live_1234567890";
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

Claudeは自動的に`scan-security`ツールを呼び出して結果を表示します。

## スキャン結果フォーマット

結果は重大度別に整理されます:

```
## ⚠️ セキュリティ脆弱性が見つかりました!

### 🔴 Critical (1件)
- **Stripe APIキー** (1行目)
  - Stripe Live APIキーがソースコードにハードコード
  - 💡 修正方法: 環境変数に保存

### 🟠 High (1件)
- **テンプレートリテラルSQL** (2行目)
  - SQLクエリがテンプレートリテラルでユーザー入力を使用
  - 💡 修正方法: プレースホルダー付きプリペアドステートメント
```

## 異なるファイルタイプをスキャン

### JavaScript/TypeScript

```
Me: このTypeScriptコードをチェックしてください

interface User {
  password: string;
}

const user: User = {
  password: "admin123"  // ハードコードされたパスワード
};
```

### Python

```
Me: このPythonコードをスキャンしてください

import os

# 脆弱
db_password = "mypassword123"
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### Java

```
Me: このJavaコードをレビューしてください

public class Config {
    private static final String API_KEY = "abc123";

    public void query(String userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
    }
}
```

### Go

```
Me: このGoコードをチェックしてください

package main

const apiKey = "sk_test_1234567890"

func query(userId string) {
    sql := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)
}
```

## インフラストラクチャファイルをスキャン

### Dockerfile

```
Me: このDockerfileをスキャンしてください

FROM node:latest
ENV SECRET_KEY="abc123"
RUN apt-get update
EXPOSE 22
```

### Kubernetes

```
Me: このKubernetesマニフェストをチェックしてください

apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
```

### Terraform

```
Me: このTerraform設定をレビューしてください

resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
```

## 結果を理解する

### 重大度レベル

- 🔴 **Critical**: 即座の対応が必要（例: 公開されたAPIキー）
- 🟠 **High**: 深刻な脆弱性（例: SQLインジェクション）
- 🟡 **Medium**: 対応すべき重要な問題（例: 弱い暗号化）
- 🟢 **Low**: 対応すべき問題（例: ベストプラクティスの欠落）

### 問題の詳細

各問題には以下が含まれます:
- **種類**: 脆弱性カテゴリ
- **行番号**: 検出された場所
- **メッセージ**: 問題の内容
- **修正**: 対処方法
- **OWASPカテゴリ**: セキュリティ分類
- **CWE ID**: Common Weakness Enumeration

## 一般的なワークフロー

### ワークフロー1: コミット前のクイックチェック

```
Me: このコードをコミット前にセキュリティチェックしてください

[コードを貼り付け]
```

### ワークフロー2: 詳細分析

```
Me: 包括的なセキュリティ分析をしてください

[コードを貼り付け]

Me: SQLインジェクションの問題を修正する方法を教えてください

Me: 完全なセキュリティレポートを生成してください
```

### ワークフロー3: インフラストラクチャレビュー

```
Me: このDockerfileをセキュリティの問題についてレビューしてください

[Dockerfileを貼り付け]

Me: このKubernetesデプロイメントもチェックしてください

[YAMLを貼り付け]
```

### ワークフロー4: 信頼できないコード

```
Me: ここで見つけたこのコードは安全ですか?

[コードを貼り付け]

Me: 念のためサンドボックスでスキャンしてください
```

## より良い結果のためのヒント

1. **コンテキストを提供**: 言語/フレームワークを明記
2. **十分なコードを含める**: スキャナーはコンテキストが必要
3. **特定のチェックを要求**: フォーカスされた分析に個別ツールを使用
4. **修正を要求**: スキャン後に「これを修正する方法は?」と聞く
5. **レポートを生成**: ドキュメント用やCI/CD統合用に`generate-security-report`を使用

## 誤検知

誤検知が発生した場合:

```
Me: これはAPIキーを検出しましたが、実は プレースホルダーです

Claude: わかります。スキャナーはパターンを検出しましたが、コンテキストが重要です。
[なぜフラグが立ったのかを説明]
```

## 次のステップ

- [CLIの使用](./cli.md) - コマンドラインインターフェースを使用
- [MCPツール](./mcp-tools.md) - 利用可能なすべてのツールについて学ぶ
- [自動修正](../features/auto-fix.md) - 修正提案を取得
