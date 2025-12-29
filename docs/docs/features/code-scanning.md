---
sidebar_position: 1
---

# Code Security Scanning

Security Scanner MCP provides comprehensive code security scanning for multiple programming languages.

## Supported Languages

- JavaScript / TypeScript
- Python
- Java
- Go

## Vulnerability Categories

### 🔑 Hardcoded Secrets

Detects API keys, passwords, and tokens hardcoded in your source code.

**What we detect:**
- AWS Access Keys and Secret Keys
- Google API Keys and OAuth Secrets
- GitHub Tokens
- Slack Tokens
- Database Connection Strings
- Private Keys (RSA, EC, SSH)
- JWT Tokens
- Stripe, Twilio, SendGrid API Keys
- Korean services (Kakao, Naver API Keys)

**Example:**

```javascript
// ❌ Vulnerable
const apiKey = "AIzaSyC1234567890abcdef";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// ✅ Secure
const apiKey = process.env.GOOGLE_API_KEY;
const awsKey = process.env.AWS_ACCESS_KEY_ID;
```

### 💉 Injection Vulnerabilities

**SQL Injection:**
```javascript
// ❌ Vulnerable - String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ Secure - Prepared statements
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
```

**NoSQL Injection:**
```javascript
// ❌ Vulnerable
db.collection.find({ username: req.body.username });

// ✅ Secure
const username = validator.escape(req.body.username);
db.collection.find({ username });
```

**Command Injection:**
```javascript
// ❌ Vulnerable
exec(`ping ${userInput}`);

// ✅ Secure
execFile('ping', [userInput]);
```

### 🌐 Cross-Site Scripting (XSS)

**Detected patterns:**
- `dangerouslySetInnerHTML` in React
- `innerHTML` / `outerHTML` assignments
- jQuery `.html()` method
- Vue `v-html` directive
- `eval()` and `new Function()`
- `document.write()`

**Example:**

```javascript
// ❌ Vulnerable
element.innerHTML = userInput;
element.dangerouslySetInnerHTML = { __html: userInput };

// ✅ Secure
element.textContent = userInput;
// Or use DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 🔐 Cryptographic Issues

**What we detect:**
- Weak hashing algorithms (MD5, SHA1)
- Insecure random number generation (`Math.random()`)
- Hardcoded encryption keys/IVs
- SSL certificate validation disabled
- Vulnerable TLS versions (1.0, 1.1)

**Example:**

```javascript
// ❌ Vulnerable
const hash = crypto.createHash('md5');
const random = Math.random();

// ✅ Secure
const hash = crypto.createHash('sha256');
const random = crypto.randomBytes(32);
```

### 🔒 Authentication & Session Security

**JWT Issues:**
- `none` algorithm allowed
- No expiration time
- Weak secret keys

**Cookie Security:**
- Missing `httpOnly` flag
- Missing `secure` flag
- Missing `sameSite` attribute

**CORS Issues:**
- Wildcard origins in production
- Credentials with wildcard

**Example:**

```javascript
// ❌ Vulnerable
res.cookie('session', token);
app.use(cors({ origin: '*', credentials: true }));

// ✅ Secure
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

### 📁 File & Path Vulnerabilities

**Path Traversal:**
```javascript
// ❌ Vulnerable
const file = fs.readFileSync(req.query.path);

// ✅ Secure
const safePath = path.join(SAFE_DIR, path.basename(req.query.path));
const file = fs.readFileSync(safePath);
```

**Dangerous File Operations:**
- Recursive deletions with user input
- Insecure file uploads
- Zip Slip vulnerabilities (Java)
- Pickle deserialization (Python)

## Usage

### Scan all vulnerability types

```
Me: Scan this code for security issues
[paste code]
```

Claude will use the `scan-security` tool which runs all scanners.

### Scan specific vulnerability types

Use individual tools for focused scanning:

- `scan-secrets` - Only secret detection
- `scan-injection` - Only injection vulnerabilities
- `scan-xss` - Only XSS risks
- `scan-crypto` - Only cryptographic issues
- `scan-auth` - Only authentication/session issues
- `scan-path` - Only file/path vulnerabilities

## External Tools Integration

When running in Docker sandbox, the scanner also uses:

- **GitLeaks v8.18.4** - Enhanced secret detection with entropy analysis
- Industry-proven patterns and rules
- Lower false positive rate

## Next Steps

- [IaC Scanning](./iac-scanning.md) - Scan infrastructure files
- [Auto-Fix](./auto-fix.md) - Get automatic fix suggestions
- [Sandbox Scanning](./sandbox.md) - Run in isolated environment
