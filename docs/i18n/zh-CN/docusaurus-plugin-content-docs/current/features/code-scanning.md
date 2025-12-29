---
sidebar_position: 1
---

# 代码安全扫描

Security Scanner MCP 为多种编程语言提供综合的代码安全扫描。

## 支持的编程语言

- JavaScript / TypeScript
- Python
- Java
- Go

## 漏洞分类

### 🔑 硬编码密钥

检测源代码中硬编码的 API 密钥、密码和令牌。

**我们检测的内容：**
- AWS 访问密钥和秘钥
- Google API 密钥和 OAuth 秘密
- GitHub 令牌
- Slack 令牌
- 数据库连接字符串
- 私钥（RSA、EC、SSH）
- JWT 令牌
- Stripe、Twilio、SendGrid API 密钥
- 韩国服务（Kakao、Naver API 密钥）

**示例：**

```javascript
// ❌ 易受攻击
const apiKey = "AIzaSyC1234567890abcdef";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// ✅ 安全
const apiKey = process.env.GOOGLE_API_KEY;
const awsKey = process.env.AWS_ACCESS_KEY_ID;
```

### 💉 注入漏洞

**SQL 注入：**
```javascript
// ❌ 易受攻击 - 字符串拼接
const query = "SELECT * FROM users WHERE id = " + userId;
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ 安全 - 预处理语句
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
```

**NoSQL 注入：**
```javascript
// ❌ 易受攻击
db.collection.find({ username: req.body.username });

// ✅ 安全
const username = validator.escape(req.body.username);
db.collection.find({ username });
```

**命令注入：**
```javascript
// ❌ 易受攻击
exec(`ping ${userInput}`);

// ✅ 安全
execFile('ping', [userInput]);
```

### 🌐 跨站脚本（XSS）

**检测的模式：**
- React 中的 `dangerouslySetInnerHTML`
- `innerHTML` / `outerHTML` 赋值
- jQuery `.html()` 方法
- Vue `v-html` 指令
- `eval()` 和 `new Function()`
- `document.write()`

**示例：**

```javascript
// ❌ 易受攻击
element.innerHTML = userInput;
element.dangerouslySetInnerHTML = { __html: userInput };

// ✅ 安全
element.textContent = userInput;
// 或使用 DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 🔐 密码学问题

**我们检测的内容：**
- 弱哈希算法（MD5、SHA1）
- 不安全的随机数生成（`Math.random()`）
- 硬编码的加密密钥/初始化向量
- 禁用 SSL 证书验证
- 易受攻击的 TLS 版本（1.0、1.1）

**示例：**

```javascript
// ❌ 易受攻击
const hash = crypto.createHash('md5');
const random = Math.random();

// ✅ 安全
const hash = crypto.createHash('sha256');
const random = crypto.randomBytes(32);
```

### 🔒 身份验证与会话安全

**JWT 问题：**
- 允许 `none` 算法
- 无过期时间
- 弱秘钥

**Cookie 安全：**
- 缺少 `httpOnly` 标志
- 缺少 `secure` 标志
- 缺少 `sameSite` 属性

**CORS 问题：**
- 生产环境中的通配符源
- 通配符凭证

**示例：**

```javascript
// ❌ 易受攻击
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

### 📁 文件和路径漏洞

**路径穿越：**
```javascript
// ❌ 易受攻击
const file = fs.readFileSync(req.query.path);

// ✅ 安全
const safePath = path.join(SAFE_DIR, path.basename(req.query.path));
const file = fs.readFileSync(safePath);
```

**危险的文件操作：**
- 递归删除用户输入
- 不安全的文件上传
- Zip Slip 漏洞（Java）
- Pickle 反序列化（Python）

## 用法

### 扫描所有漏洞类型

```
我：扫描此代码以查找安全问题
[粘贴代码]
```

Claude 将使用运行所有扫描工具的 `scan-security` 工具。

### 扫描特定漏洞类型

使用单个工具进行有针对性的扫描：

- `scan-secrets` - 仅密钥检测
- `scan-injection` - 仅注入漏洞
- `scan-xss` - 仅 XSS 风险
- `scan-crypto` - 仅密码学问题
- `scan-auth` - 仅身份验证/会话问题
- `scan-path` - 仅文件/路径漏洞

## 外部工具集成

在 Docker 沙箱中运行时，扫描工具还使用：

- **GitLeaks v8.18.4** - 增强的密钥检测，包含熵分析
- 业界验证的模式和规则
- 更低的误报率

## 下一步

- [IaC 扫描](./iac-scanning.md) - 扫描基础设施文件
- [自动修复](./auto-fix.md) - 获取自动修复建议
- [沙箱扫描](./sandbox.md) - 在隔离环境中运行
