---
sidebar_position: 3
---

# MCPツールリファレンス

Security Scanner MCPのすべてのツールの完全なリファレンス。

## コアスキャンツール

### scan-security

**説明**: 包括的なセキュリティスキャン - すべてのチェックを一度に実行

**使用方法**: 一般的なスキャンに最適

```
Me: このコードをセキュリティの問題についてスキャンしてください
```

**実施内容**:
- 7つのスキャナーを同時に実行
- 結果を組み合わせる
- 包括的なレポートを返す

### scan-secrets

**説明**: ハードコードされたシークレットを検出

**検出対象**:
- APIキー（AWS、Google、GitHub、Stripe等）
- パスワードとトークン
- データベース接続文字列
- 秘密鍵
- OAuthシークレット

**使用方法**:
```
Me: このコードにハードコードされたシークレットがないかチェックしてください
```

### scan-injection

**説明**: SQL/NoSQL/コマンドインジェクション脆弱性を検出

**検出対象**:
- SQLインジェクション（文字列連結、テンプレートリテラル）
- NoSQLインジェクション（MongoDB）
- コマンドインジェクション（exec、spawn、system）
- LDAPインジェクション

**使用方法**:
```
Me: インジェクション脆弱性をスキャンしてください
```

### scan-xss

**説明**: Cross-Site Scriptingのリスクを特定

**検出対象**:
- `dangerouslySetInnerHTML`（React）
- `innerHTML` / `outerHTML`
- jQuery `.html()`
- Vue `v-html`
- `eval()` / `new Function()`

**使用方法**:
```
Me: XSS脆弱性をチェックしてください
```

### scan-crypto

**説明**: 暗号化の脆弱性をチェック

**検出対象**:
- 弱いハッシング（MD5、SHA1）
- 安全でない乱数（`Math.random`）
- ハードコードされたキー/IV
- SSL検証無効化
- 脆弱なTLSバージョン

**使用方法**:
```
Me: 暗号化セキュリティを分析してください
```

### scan-auth

**説明**: 認証とセッションセキュリティを監査

**検出対象**:
- JWTのミスコンフィグレーション
- 安全でないクッキー
- CORSワイルドカード
- 弱いパスワードポリシー
- セッション固定のリスク

**使用方法**:
```
Me: 認証セキュリティをレビューしてください
```

### scan-path

**説明**: ファイルとパスの脆弱性を検出

**検出対象**:
- パストラバーサル
- 危険なファイル操作
- 安全でないファイルアップロード
- Zip Slip（Java）
- Pickleデシリアライゼーション（Python）

**使用方法**:
```
Me: パストラバーサルの問題をチェックしてください
```

### scan-dependencies

**説明**: 脆弱な依存関係をチェック

**チェック対象**:
- package.json（npm audit）
- requirements.txt（Python）
- go.mod（Go）

**使用方法**:
```
Me: 依存関係の脆弱性をスキャンしてください
```

## インフラストラクチャツール

### scan-iac

**説明**: Infrastructure as Code ファイルをスキャン

**サポート対象**:
- Dockerfile（CIS Dockerベンチマーク）
- Kubernetes YAML（ポッドセキュリティ標準）
- Terraform HCL（マルチクラウド）

**使用方法**:
```
Me: このDockerfileをスキャンしてください
```

## 高度なツール

### get-fix-suggestion

**説明**: 自動生成された修正コードを取得

**返す内容**:
- 修正前/修正後のコード比較
- 説明
- 代替ソリューション

**使用方法**:
```
Me: このSQLインジェクションを修正するにはどうしたらいいですか?
```

**パラメータ**:
- `issue`: 脆弱性の説明
- `code`: 元の脆弱なコード
- `language`: プログラミング言語

### generate-security-report

**説明**: 包括的なセキュリティレポートを作成

**生成内容**:
- Mermaidダイアグラム（円グラフ、棒グラフ、フローチャート）
- SARIF形式（GitHub Code Scanning互換）
- CVE/OWASP情報
- 攻撃シナリオ分析

**使用方法**:
```
Me: ダイアグラム付きの完全なセキュリティレポートを生成してください
```

**出力内容**:
- 全体的なサマリー
- 重大度分布チャート
- 脆弱性カテゴリチャート
- 攻撃シナリオのフローチャート
- CI/CD統合用のSARIF JSON

### scan-in-sandbox

**説明**: Docker隔離環境でスキャンを実行

**機能**:
- メモリ/CPU制限
- ネットワーク隔離
- 外部ツール（Trivy、Checkov、GitLeaks）

**使用方法**:
```
Me: このコードをサンドボックスでスキャンしてください
```

**セキュリティ設定**:
- メモリ: 128MB～2GB
- CPU: 0.1～2.0コア
- タイムアウト: 5秒～5分
- ネットワーク: 無効
- 特権: 最小

## ツールパラメータ

### 共通パラメータ

すべてのスキャンツールは以下を受け入れます:
- `code`: スキャンするソースコード（文字列）
- `language`: プログラミング言語（オプション、自動検出）
- `filename`: 元のファイル名（オプション）

### 言語検出

自動検出される言語:
- JavaScript
- TypeScript
- Python
- Java
- Go

## ツール レスポンスフォーマット

### 標準的な問題フォーマット

```typescript
interface SecurityIssue {
  type: string;          // 脆弱性の種類
  severity: string;      // critical | high | medium | low
  message: string;       // 人間が読める説明
  fix: string;          // 対処法の提案
  line?: number;        // 行番号（1から始まる）
  match?: string;       // マッチしたテキスト（シークレットはマスク）
  owaspCategory?: string;  // OWASP Top 10マッピング
  cweId?: string;       // CWE識別子
  metadata?: object;    // ツール固有データ
}
```

### スキャン結果フォーマット

```typescript
interface ScanResult {
  success: boolean;
  issues: SecurityIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}
```

## エラーハンドリング

ツールは標準フォーマットでエラーを返します:

```json
{
  "success": false,
  "error": "エラー説明",
  "code": "ERROR_CODE"
}
```

一般的なエラーコード:
- `INVALID_INPUT`: 無効なコードまたはパラメータ
- `LANGUAGE_NOT_SUPPORTED`: サポートされていない言語
- `SCAN_TIMEOUT`: スキャンが時間制限を超過
- `DOCKER_NOT_AVAILABLE`: Dockerがインストールされていない（サンドボックスのみ）

## ベストプラクティス

1. **まずscan-securityを使用**: 全体的な概要を取得
2. **個別スキャナーをターゲット化**: 詳細な分析用
3. **修正を要求**: スキャン後にget-fix-suggestionを使用
4. **レポートを生成**: ドキュメントとCI/CD用
5. **信頼できないコードをサンドボックスで**: 不明なソースには使用

## 次のステップ

- [基本的な使用方法](./basic-usage.md) - 一般的な使用パターンを学ぶ
- [高度な機能](../advanced/external-tools.md) - 外部ツール統合
- [APIリファレンス](../reference/api.md) - プログラム的なAPI
