---
sidebar_position: 1
---

# 漏洞参考

Security Scanner MCP 检测的所有漏洞类型的完整参考。

## OWASP Top 10:2021 映射

### A01:2021 - 破损访问控制

**我们检测的内容**：
- 缺少授权检查
- 不安全的直接对象引用
- 路径穿越漏洞

**示例**：
```javascript
// 易受攻击
app.get('/user/:id/data', (req, res) => {
  const data = getUserData(req.params.id); // 无身份验证检查
  res.json(data);
});
```

### A02:2021 - 密码学故障

**我们检测的内容**：
- 弱哈希算法（MD5、SHA1）
- 硬编码的加密密钥
- 不安全的随机数生成
- 缺少 SSL/TLS
- 易受攻击的 TLS 版本

**示例**：
```javascript
// 易受攻击
const hash = crypto.createHash('md5');
const key = "hardcoded_key_123";
```

### A03:2021 - 注入

**我们检测的内容**：
- SQL 注入
- NoSQL 注入
- 命令注入
- LDAP 注入
- 表达式语言注入

**示例**：
```javascript
// SQL 注入
const query = `SELECT * FROM users WHERE id = ${userId}`;

// 命令注入
exec(`ping ${userInput}`);

// NoSQL 注入
db.users.find({ username: req.body.username });
```

### A04:2021 - 不安全的设计

**我们检测的内容**：
- 缺少安全控制
- 不充分的输入验证
- 业务逻辑缺陷

### A05:2021 - 安全配置错误

**我们检测的内容**：
- 默认凭证
- 不必要的功能启用
- 不适当的错误处理
- 缺少安全头
- IaC 配置错误

**示例**：
```javascript
// 详细错误消息
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack }); // 泄露内部信息
});
```

### A06:2021 - 易受攻击和过时的组件

**我们检测的内容**：
- 依赖项中的已知 CVE
- 过时的包
- 易受攻击的框架

**检测方法**：
- npm audit 集成
- CVE 数据库查询
- 版本检查

### A07:2021 - 识别和身份验证故障

**我们检测的内容**：
- 硬编码凭证
- 弱密码策略
- 不安全的会话管理
- 缺少 MFA
- JWT 配置错误

**示例**：
```javascript
// 硬编码凭证
const dbPassword = "admin123";

// 弱 JWT
jwt.sign(payload, 'weak_secret', { algorithm: 'none' });

// 不安全的 Cookie
res.cookie('session', token); // 缺少 httpOnly、secure 标志
```

### A08:2021 - 软件和数据完整性故障

**我们检测的内容**：
- 缺少完整性检查
- 不安全的反序列化
- 未验证的更新

**示例**：
```python
# 不安全的反序列化
import pickle
data = pickle.loads(user_input)
```

### A09:2021 - 安全日志和监控故障

**我们检测的内容**：
- 缺少审计日志
- 监控不足
- 日志注入

### A10:2021 - 服务器端请求伪造（SSRF）

**我们检测的内容**：
- 未验证的 URL
- 内部网络访问
- 云元数据访问

**示例**：
```javascript
// SSRF
const url = req.query.url;
axios.get(url); // 无验证
```

## CWE 映射

### CWE-78：OS 命令注入

```javascript
// 易受攻击
child_process.exec(`git clone ${repo_url}`);

// 安全
child_process.execFile('git', ['clone', repo_url]);
```

### CWE-79：跨站脚本（XSS）

```javascript
// 易受攻击
element.innerHTML = userInput;

// 安全
element.textContent = userInput;
```

### CWE-89：SQL 注入

```javascript
// 易受攻击
db.query(`SELECT * FROM users WHERE id = ${id}`);

// 安全
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

### CWE-200：信息泄露

```javascript
// 易受攻击
console.log(error.stack);
res.json({ error: error.message, stack: error.stack });

// 安全
logger.error(error);
res.json({ error: 'Internal server error' });
```

### CWE-259：硬编码密码

```javascript
// 易受攻击
const password = "admin123";

// 安全
const password = process.env.DB_PASSWORD;
```

### CWE-327：破损密码学

```javascript
// 易受攻击
crypto.createHash('md5');

// 安全
crypto.createHash('sha256');
```

### CWE-352：跨站请求伪造（CSRF）

```javascript
// 易受攻击
app.post('/transfer', (req, res) => {
  transfer(req.body.amount);
});

// 安全
app.use(csrf());
app.post('/transfer', csrfProtection, (req, res) => {
  transfer(req.body.amount);
});
```

### CWE-434：不受限的上传

```javascript
// 易受攻击
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

### CWE-502：不受信任数据的反序列化

```javascript
// 易受攻击
const obj = JSON.parse(userInput);
eval(userInput);

// 安全
const obj = JSON.parse(userInput);
// 在使用前验证 obj 结构
```

### CWE-611：XML 外部实体（XXE）

```javascript
// 易受攻击
const parser = new xml2js.Parser();
parser.parseString(xmlInput);

// 安全
const parser = new xml2js.Parser({
  explicitArray: false,
  xmlns: false
});
```

### CWE-798：硬编码凭证

```javascript
// 易受攻击
const apiKey = "sk_live_1234567890";

// 安全
const apiKey = process.env.API_KEY;
```

### CWE-829：包含来自不受信任控制区的功能

```javascript
// 易受攻击
const module = require(userProvidedPath);

// 安全
const allowedModules = ['lodash', 'axios'];
if (allowedModules.includes(moduleName)) {
  const module = require(moduleName);
}
```

## 严重程度定义

### 🔴 严重

**CVSS 9.0-10.0**

需要立即采取行动：
- 远程代码执行
- 身份验证绕过
- 暴露凭证
- 数据泄露潜力

**响应时间**：立即修复（< 24 小时）

### 🟠 高

**CVSS 7.0-8.9**

需要紧急采取行动：
- SQL/NoSQL 注入
- XSS 漏洞
- 权限提升
- 敏感数据暴露

**响应时间**：1 周内修复

### 🟡 中

**CVSS 4.0-6.9**

应该解决：
- 信息披露
- 弱密码学
- 缺少安全头
- 会话问题

**响应时间**：1 个月内修复

### 🟢 低

**CVSS 0.1-3.9**

推荐修复：
- 最佳实践违规
- 深层防御改进
- 信息性发现

**响应时间**：下一版本修复

## 常见模式

### 密钥检测模式

```regex
AWS Access Key: AKIA[0-9A-Z]{16}
Google API Key: AIza[0-9A-Za-z-_]{35}
GitHub Token: ghp_[0-9a-zA-Z]{36}
Slack Token: xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}
```

### 注入模式

```javascript
// SQL 注入指标
"SELECT * FROM " + table
`SELECT * FROM ${table}`
"WHERE id = " + userId

// 命令注入指标
exec(userInput)
spawn(userInput)
system(userInput)
```

### XSS 模式

```javascript
// 危险赋值
element.innerHTML = userInput
element.outerHTML = userInput
$().html(userInput)

// 危险函数
eval(userInput)
Function(userInput)
document.write(userInput)
```

## 下一步

- [配置](./configuration.md) - 自定义检测规则
- [API 参考](./api.md) - 编程使用
- [代码扫描](../features/code-scanning.md) - 了解检测详情
