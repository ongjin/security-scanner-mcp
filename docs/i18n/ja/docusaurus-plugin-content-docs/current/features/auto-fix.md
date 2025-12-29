---
sidebar_position: 3
---

# 自動修正提案

検出された脆弱性に対するAI生成のコード修正を取得します。

## 動作方法

`get-fix-suggestion`ツールは以下を提供します:
1. **修正前/修正後のコード比較**
2. **脆弱性の説明**
3. **段階的な対処**
4. **代替方案**（該当する場合）

## サポートされている脆弱性タイプ

### ハードコードされたシークレット

```typescript
// 元のコード（脆弱）
const apiKey = "AIzaSyC1234567890abcdef";

// 修正後
const apiKey = process.env.GOOGLE_API_KEY;

// 追加の推奨事項:
// 1. .envファイルにAPIキーを追加
// 2. .envを.gitignoreに追加
// 3. Google Cloud ConsoleでAPIキー制限を使用
```

### SQLインジェクション

```javascript
// 元のコード（脆弱）
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// 修正後 - プリペアドステートメント
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

// 代替 - ORM
const user = await User.findByPk(userId);
```

### XSS脆弱性

```javascript
// 元のコード（脆弱）
element.innerHTML = userInput;

// 修正後 - オプション1: テキストコンテンツ
element.textContent = userInput;

// 修正後 - オプション2: DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 弱い暗号化

```javascript
// 元のコード（脆弱）
const hash = crypto.createHash('md5').update(password).digest('hex');

// 修正後
const hash = await bcrypt.hash(password, 10);

// または一般的なハッシング
const hash = crypto.createHash('sha256').update(data).digest('hex');
```

### 安全でない認証

```javascript
// 元のコード（脆弱）
res.cookie('session', sessionId);

// 修正後
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 3600000 // 1時間
});
```

### パストラバーサル

```javascript
// 元のコード（脆弱）
const file = fs.readFileSync(userPath);

// 修正後
const path = require('path');
const safePath = path.join(__dirname, 'uploads', path.basename(userPath));

// パスが許可されたディレクトリ内であることを確認
if (!safePath.startsWith(path.join(__dirname, 'uploads'))) {
  throw new Error('Invalid path');
}

const file = fs.readFileSync(safePath);
```

## 使用方法

### 特定の問題に対する修正を取得

```
Me: このSQLインジェクション脆弱性を修正する方法は?

const query = `SELECT * FROM users WHERE email = '${email}'`;
```

### スキャン後に修正を取得

```
Me: このコードをスキャンして、問題を修正する方法を教えてください

[コードを貼り付け]

Claude: [スキャンを実行し、問題を検出]

Me: XSSの脆弱性を修正する方法を教えてください

Claude: [get-fix-suggestionを呼び出し]
```

## AST ベースのコード変換

特定の脆弱性に対して、ツールはAbstract Syntax Tree（AST）分析を使用して正確な修正を提供します:

- 正確な行と列の番号
- コンテキストを考慮した提案
- コードフォーマットの維持
- コメントの保持

## ベストプラクティス

1. **適用前にレビュー**: 実装前に修正を理解
2. **徹底的にテスト**: 修正が機能性を損なわないことを確認
3. **代替案を検討**: ユースケースに最適なソリューションを選択
4. **依存関係を更新**: 修正に新しいパッケージが必要な場合がある
5. **変更を記録**: セキュリティ改善を説明するコメントを追加

## 制限事項

- すべての脆弱性を自動的に修正することはできません
- いくつかの問題はアーキテクチャ変更が必要
- 人間によるレビューは常に推奨されます
- コンテキスト固有の修正には調整が必要な場合があります

## 高度な使用方法

### 複数の修正オプションを要求

```
Me: この認証の問題を修正するさまざまな方法を教えてください
```

### 説明付きで修正を取得

```
Me: なぜこれが脆弱で、どのように修正するのかを説明してください
```

### フレームワーク固有の修正

```
Me: React/Vue/Angularでこれを修正する方法は?
```

## 次のステップ

- [コードスキャン](./code-scanning.md) - 脆弱性検出について学ぶ
- [IaCスキャン](./iac-scanning.md) - インフラストラクチャミスコンフィグレーションを修正
- [レポート](../advanced/reporting.md) - 包括的なレポートを生成
