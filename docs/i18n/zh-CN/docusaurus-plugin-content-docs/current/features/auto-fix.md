---
sidebar_position: 3
---

# 自动修复建议

获取为检测到的漏洞生成的 AI 修复代码。

## 工作原理

`get-fix-suggestion` 工具提供：
1. **代码对比**（修改前/修改后）
2. **漏洞解释**
3. **分步补救**
4. **替代方案**（如适用）

## 支持的漏洞类型

### 硬编码密钥

```typescript
// 原始（易受攻击）
const apiKey = "AIzaSyC1234567890abcdef";

// 已修复
const apiKey = process.env.GOOGLE_API_KEY;

// 额外建议：
// 1. 将 API 密钥添加到 .env 文件
// 2. 将 .env 添加到 .gitignore
// 3. 在 Google Cloud Console 中使用 API 密钥限制
```

### SQL 注入

```javascript
// 原始（易受攻击）
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// 已修复 - 预处理语句
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

// 替代 - ORM
const user = await User.findByPk(userId);
```

### XSS 漏洞

```javascript
// 原始（易受攻击）
element.innerHTML = userInput;

// 已修复 - 选项 1：文本内容
element.textContent = userInput;

// 已修复 - 选项 2：DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 弱密码学

```javascript
// 原始（易受攻击）
const hash = crypto.createHash('md5').update(password).digest('hex');

// 已修复
const hash = await bcrypt.hash(password, 10);

// 或用于通用哈希
const hash = crypto.createHash('sha256').update(data).digest('hex');
```

### 不安全的身份验证

```javascript
// 原始（易受攻击）
res.cookie('session', sessionId);

// 已修复
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 3600000 // 1 小时
});
```

### 路径穿越

```javascript
// 原始（易受攻击）
const file = fs.readFileSync(userPath);

// 已修复
const path = require('path');
const safePath = path.join(__dirname, 'uploads', path.basename(userPath));

// 验证路径在允许的目录内
if (!safePath.startsWith(path.join(__dirname, 'uploads'))) {
  throw new Error('Invalid path');
}

const file = fs.readFileSync(safePath);
```

## 用法

### 获取特定问题的修复

```
我：如何修复这个 SQL 注入漏洞？

const query = `SELECT * FROM users WHERE email = '${email}'`;
```

### 扫描后获取修复

```
我：扫描此代码并向我展示如何修复问题

[粘贴代码]

Claude：[运行扫描，查找问题]

我：展示我如何修复 XSS 漏洞

Claude：[调用 get-fix-suggestion]
```

## 基于 AST 的代码转换

对于某些漏洞，工具使用抽象语法树（AST）分析来提供精确的修复：

- 确切的行号和列号
- 上下文感知的建议
- 维持代码格式
- 保留注释

## 最佳实践

1. **应用前检查**：在实施前理解修复
2. **彻底测试**：验证修复不会破坏功能
3. **考虑替代方案**：为您的用例选择最佳解决方案
4. **更新依赖项**：有时修复需要新包
5. **记录更改**：添加注释说明安全改进

## 限制

- 无法自动修复所有漏洞
- 某些问题需要架构更改
- 始终建议人工审查
- 特定上下文的修复可能需要调整

## 高级用法

### 请求多个修复选项

```
我：展示修复此身份验证问题的不同方式
```

### 获取解释和修复

```
我：解释为什么这是易受攻击的，以及如何修复它
```

### 框架特定的修复

```
我：我如何在 React/Vue/Angular 中修复这个问题？
```

## 下一步

- [代码扫描](./code-scanning.md) - 了解漏洞检测
- [IaC 扫描](./iac-scanning.md) - 修复基础设施配置错误
- [报告](../advanced/reporting.md) - 生成综合报告
