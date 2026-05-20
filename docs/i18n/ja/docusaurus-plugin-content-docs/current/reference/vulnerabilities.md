---
sidebar_position: 1
---

# 脆弱性リファレンス

Security Scanner MCPで検出されるすべての脆弱性タイプの完全なリファレンス。

## 1.2.0の検出セマンティクス

JavaScript / TypeScriptのinjection、XSS、crypto、auth、path検出はASTベースです。

- 関数パラメータtaintがSQL、MongoDB、command、file-system sinkに到達するフローを検出します。
- `req.body.file` → `f` → `normalized` → `fs.readFile`のような複数段階の変数フローを検出します。
- `res.setHeader('Access-Control-Allow-Origin', '*')`のCORSワイルドカードを検出します。
- 複数段階taintによる平文パスワード保存を検出します。
- `innerHTML`の静的なリテラルHTMLはXSSとして報告せず、動的な値だけを報告します。

## OWASP Top 10:2021マッピング

### A01:2021 - Broken Access Control

**検出対象**:
- 認可チェックの欠落
- 安全でない直接オブジェクト参照
- パストラバーサル脆弱性

**例**:
```javascript
// 脆弱
app.get('/user/:id/data', (req, res) => {
  const data = getUserData(req.params.id); // 認可チェックなし
  res.json(data);
});
```

### A02:2021 - 暗号化の失敗

**検出対象**:
- 弱いハッシング（MD5、SHA1）
- ハードコードされた暗号化キー
- 安全でない乱数生成
- SSL/TLSなし
- 脆弱なTLSバージョン

**例**:
```javascript
// 脆弱
const hash = crypto.createHash('md5');
const key = "hardcoded_key_123";
```

### A03:2021 - インジェクション

**検出対象**:
- SQLインジェクション
- NoSQLインジェクション
- コマンドインジェクション
- LDAPインジェクション
- 式言語インジェクション

**例**:
```javascript
// SQLインジェクション
const query = `SELECT * FROM users WHERE id = ${userId}`;

// コマンドインジェクション
exec(`ping ${userInput}`);

// NoSQLインジェクション
db.users.find({ username: req.body.username });
```

### A04:2021 - 安全でない設計

**検出対象**:
- セキュリティコントロール欠落
- 不十分な入力検証
- ビジネスロジックの欠陥

### A05:2021 - セキュリティミスコンフィグレーション

**検出対象**:
- デフォルト認証情報
- 不要な機能が有効
- 不正なエラーハンドリング
- セキュリティヘッダーなし
- IaCミスコンフィグレーション

**例**:
```javascript
// 詳細なエラーメッセージ
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack }); // 内部を公開
});
```

### A06:2021 - 脆弱で古いコンポーネント

**検出対象**:
- 依存関係の既知のCVE
- 古いパッケージ
- 脆弱なフレームワーク

**検出方法**:
- npm audit統合
- CVEデータベース検索
- バージョンチェック

### A07:2021 - 認証と認可の失敗

**検出対象**:
- ハードコードされた認証情報
- 弱いパスワードポリシー
- 安全でないセッション管理
- MFAなし
- JWTのミスコンフィグレーション

**例**:
```javascript
// ハードコードされた認証情報
const dbPassword = "admin123";

// 弱いJWT
jwt.sign(payload, 'weak_secret', { algorithm: 'none' });

// 安全でないクッキー
res.cookie('session', token); // httpOnlyとsecureフラグがない
```

### A08:2021 - ソフトウェアとデータの整合性の失敗

**検出対象**:
- 整合性チェックの欠落
- 安全でないデシリアライゼーション
- 検証されていないアップデート

**例**:
```python
# 安全でないデシリアライゼーション
import pickle
data = pickle.loads(user_input)
```

### A09:2021 - セキュリティログと監視の失敗

**検出対象**:
- 監査ログの欠落
- 不十分な監視
- ログインジェクション

### A10:2021 - Server-Side Request Forgery（SSRF）

**検出対象**:
- 検証されていないURL
- 内部ネットワークアクセス
- クラウドメタデータアクセス

**例**:
```javascript
// SSRF
const url = req.query.url;
axios.get(url); // 検証なし
```

## CWEマッピング

### CWE-78: OS コマンドインジェクション

```javascript
// 脆弱
child_process.exec(`git clone ${repo_url}`);

// 安全
child_process.execFile('git', ['clone', repo_url]);
```

### CWE-79: Cross-Site Scripting（XSS）

```javascript
// 脆弱
element.innerHTML = userInput;

// 安全
element.textContent = userInput;
```

### CWE-89: SQLインジェクション

```javascript
// 脆弱
db.query(`SELECT * FROM users WHERE id = ${id}`);

// 安全
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

### CWE-200: 情報公開

```javascript
// 脆弱
console.log(error.stack);
res.json({ error: error.message, stack: error.stack });

// 安全
logger.error(error);
res.json({ error: 'Internal server error' });
```

### CWE-259: ハードコードされたパスワード

```javascript
// 脆弱
const password = "admin123";

// 安全
const password = process.env.DB_PASSWORD;
```

### CWE-327: 破損した暗号化

```javascript
// 脆弱
crypto.createHash('md5');

// 安全
crypto.createHash('sha256');
```

### CWE-352: Cross-Site Request Forgery（CSRF）

```javascript
// 脆弱
app.post('/transfer', (req, res) => {
  transfer(req.body.amount);
});

// 安全
app.use(csrf());
app.post('/transfer', csrfProtection, (req, res) => {
  transfer(req.body.amount);
});
```

### CWE-434: 制限のないアップロード

```javascript
// 脆弱
app.post('/upload', (req, res) => {
  const file = req.files.upload;
  file.mv(`./uploads/${file.name}`);
});

// 安全
const allowedTypes = ['image/jpeg', 'image/png'];
if (!allowedTypes.includes(file.mimetype)) {
  return res.status(400).send('Invalid file type');
}
```

### CWE-502: 信頼できないデータのデシリアライゼーション

```javascript
// 脆弱
const obj = JSON.parse(userInput);
eval(userInput);

// 安全
const obj = JSON.parse(userInput);
// 使用前にobjの構造を検証
```

### CWE-611: XML外部エンティティ（XXE）

```javascript
// 脆弱
const parser = new xml2js.Parser();
parser.parseString(xmlInput);

// 安全
const parser = new xml2js.Parser({
  explicitArray: false,
  xmlns: false
});
```

### CWE-798: ハードコードされた認証情報

```javascript
// 脆弱
const apiKey = "sk_live_1234567890";

// 安全
const apiKey = process.env.API_KEY;
```

### CWE-829: 信頼できない制御領域から機能を含む

```javascript
// 脆弱
const module = require(userProvidedPath);

// 安全
const allowedModules = ['lodash', 'axios'];
if (allowedModules.includes(moduleName)) {
  const module = require(moduleName);
}
```

## 重大度の定義

### 🔴 Critical

**CVSS 9.0-10.0**

即座の対応が必要:
- リモートコード実行
- 認証バイパス
- 公開されたクレデンシャル
- データ漏洩の可能性

**対応時間**: すぐに修正（24時間以内）

### 🟠 High

**CVSS 7.0-8.9**

緊急の対応が必要:
- SQLインジェクション
- XSS脆弱性
- 権限昇格
- 機密データ公開

**対応時間**: 1週間以内に修正

### 🟡 Medium

**CVSS 4.0-6.9**

対応すべき問題:
- 情報公開
- 弱い暗号化
- セキュリティヘッダーなし
- セッション問題

**対応時間**: 1か月以内に修正

### 🟢 Low

**CVSS 0.1-3.9**

推奨される修正:
- ベストプラクティス違反
- 多層防御の改善
- 情報提供

**対応時間**: 次のリリースで修正

## 一般的なパターン

### シークレット検出パターン

```regex
AWS Access Key: AKIA[0-9A-Z]{16}
Google API Key: AIza[0-9A-Za-z-_]{35}
GitHub Token: ghp_[0-9a-zA-Z]{36}
Slack Token: xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}
```

### インジェクションパターン

```javascript
// SQLインジェクションの指標
"SELECT * FROM " + table
`SELECT * FROM ${table}`
"WHERE id = " + userId

// コマンドインジェクションの指標
exec(userInput)
spawn(userInput)
system(userInput)
```

### XSSパターン

```javascript
// 危険な代入
element.innerHTML = userInput
element.outerHTML = userInput
$().html(userInput)

// 危険な関数
eval(userInput)
Function(userInput)
document.write(userInput)
```

## 次のステップ

- [設定](./configuration.md) - 検出ルールをカスタマイズ
- [APIリファレンス](./api.md) - プログラム的な使用法
- [コードスキャン](../features/code-scanning.md) - 検出詳細を学ぶ
