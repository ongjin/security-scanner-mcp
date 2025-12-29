---
sidebar_position: 1
---

# コードセキュリティスキャン

Security Scanner MCPは複数のプログラミング言語を対象とした包括的なコードセキュリティスキャンを提供します。

## サポートされている言語

- JavaScript / TypeScript
- Python
- Java
- Go

## 脆弱性カテゴリ

### 🔑 ハードコードされたシークレット

ソースコード内にハードコードされたAPIキー、パスワード、トークンを検出します。

**検出対象:**
- AWS アクセスキーとシークレットキー
- Google APIキーとOAuthシークレット
- GitHubトークン
- Slackトークン
- データベース接続文字列
- 秘密鍵（RSA、EC、SSH）
- JWTトークン
- Stripe、Twilio、SendGrid APIキー
- 韓国サービス（KakaoやNaverのAPIキー）

**例:**

```javascript
// ❌ 脆弱
const apiKey = "AIzaSyC1234567890abcdef";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// ✅ 安全
const apiKey = process.env.GOOGLE_API_KEY;
const awsKey = process.env.AWS_ACCESS_KEY_ID;
```

### 💉 インジェクション脆弱性

**SQLインジェクション:**
```javascript
// ❌ 脆弱 - 文字列連結
const query = "SELECT * FROM users WHERE id = " + userId;
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ 安全 - プリペアドステートメント
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
```

**NoSQLインジェクション:**
```javascript
// ❌ 脆弱
db.collection.find({ username: req.body.username });

// ✅ 安全
const username = validator.escape(req.body.username);
db.collection.find({ username });
```

**コマンドインジェクション:**
```javascript
// ❌ 脆弱
exec(`ping ${userInput}`);

// ✅ 安全
execFile('ping', [userInput]);
```

### 🌐 Cross-Site Scripting（XSS）

**検出パターン:**
- Reactの`dangerouslySetInnerHTML`
- `innerHTML` / `outerHTML`代入
- jQuery `.html()`メソッド
- Vue `v-html`ディレクティブ
- `eval()`と`new Function()`
- `document.write()`

**例:**

```javascript
// ❌ 脆弱
element.innerHTML = userInput;
element.dangerouslySetInnerHTML = { __html: userInput };

// ✅ 安全
element.textContent = userInput;
// またはDOMPurifyを使用
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 🔐 暗号化の問題

**検出対象:**
- 弱いハッシュアルゴリズム（MD5、SHA1）
- 安全でない乱数生成（`Math.random()`）
- ハードコードされた暗号化キー/IV
- SSL証明書検証無効化
- 脆弱なTLSバージョン（1.0、1.1）

**例:**

```javascript
// ❌ 脆弱
const hash = crypto.createHash('md5');
const random = Math.random();

// ✅ 安全
const hash = crypto.createHash('sha256');
const random = crypto.randomBytes(32);
```

### 🔒 認証とセッションセキュリティ

**JWT問題:**
- `none`アルゴリズムが許可
- 有効期限なし
- 弱い秘密鍵

**クッキーセキュリティ:**
- `httpOnly`フラグなし
- `secure`フラグなし
- `sameSite`属性なし

**CORS問題:**
- 本番環境でのワイルドカードオリジン
- ワイルドカードでのクレデンシャル

**例:**

```javascript
// ❌ 脆弱
res.cookie('session', token);
app.use(cors({ origin: '*', credentials: true }));

// ✅ 安全
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
app.use(cors({
  origin: 'https://yourdomain.com',
  credentials: true
}));
```

### 📁 ファイルとパスの脆弱性

**パストラバーサル:**
```javascript
// ❌ 脆弱
const file = fs.readFileSync(req.query.path);

// ✅ 安全
const safePath = path.join(SAFE_DIR, path.basename(req.query.path));
const file = fs.readFileSync(safePath);
```

**危険なファイル操作:**
- ユーザー入力による再帰削除
- 安全でないファイルアップロード
- Zip Slip脆弱性（Java）
- Pickleデシリアライゼーション（Python）

## 使用方法

### すべての脆弱性タイプをスキャン

```
Me: このコードをセキュリティの問題についてスキャンしてください
[コードを貼り付け]
```

Claudeは全スキャナーを実行する`scan-security`ツールを使用します。

### 特定の脆弱性タイプをスキャン

フォーカスされたスキャンに個別ツールを使用:

- `scan-secrets` - シークレット検出のみ
- `scan-injection` - インジェクション脆弱性のみ
- `scan-xss` - XSSリスクのみ
- `scan-crypto` - 暗号化の問題のみ
- `scan-auth` - 認証/セッションの問題のみ
- `scan-path` - ファイル/パスの脆弱性のみ

## 外部ツール統合

Dockerサンドボックスで実行する場合、スキャナーは以下も使用します:

- **GitLeaks v8.18.4** - エントロピー分析によるシークレット検出の強化
- 業界が実証した検出パターンとルール
- 誤検知の少ない

## 次のステップ

- [IaCスキャン](./iac-scanning.md) - インフラストラクチャファイルをスキャン
- [自動修正](./auto-fix.md) - 自動修正提案を取得
- [サンドボックススキャン](./sandbox.md) - 隔離環境で実行
