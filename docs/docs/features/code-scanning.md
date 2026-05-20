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

## AST-Aware Detection in 1.2.0

For JavaScript and TypeScript, the injection, XSS, crypto, auth, and path scanners parse code into an AST before matching security sinks. This improves correctness over regex-only scanning:

- Function-parameter taint is detected.
- Multi-hop variable chains are detected.
- `innerHTML` literal HTML strings are ignored, while dynamic assignments are still reported.
- `res.setHeader('Access-Control-Allow-Origin', '*')` and `res.header(...)` CORS wildcards are reported.
- Python / Java / Go and JS/TS parse failures still use the regex path.

```typescript
function readUser(input) {
  db.query(`SELECT * FROM users WHERE id = ${input}`);
}

const file = req.body.file;
const normalized = file;
fs.readFile(normalized, cb);

readUser(req.body.userId);
```

Both the function-parameter SQL flow and the multi-hop file path flow are reported.

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

**Function parameter taint:**
```javascript
// ❌ Vulnerable
function search(input) {
  db.query(`SELECT * FROM users WHERE name = ${input}`);
}
search(req.body.name);
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

// ✅ Not reported as XSS in 1.2.0: static literal HTML
element.innerHTML = '<strong>Saved</strong>';

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
- Wildcards set via `res.setHeader('Access-Control-Allow-Origin', '*')`

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

// ❌ Vulnerable in 1.2.0: multi-hop variable flow
const requested = req.body.file;
const normalized = requested;
fs.readFile(normalized, cb);

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
