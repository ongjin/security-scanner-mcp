---
sidebar_position: 1
---

# Vulnerability Reference

Complete reference of all vulnerability types detected by Security Scanner MCP.

## OWASP Top 10:2021 Mapping

### A01:2021 - Broken Access Control

**What we detect**:
- Missing authorization checks
- Insecure direct object references
- Path traversal vulnerabilities

**Example**:
```javascript
// Vulnerable
app.get('/user/:id/data', (req, res) => {
  const data = getUserData(req.params.id); // No auth check
  res.json(data);
});
```

### A02:2021 - Cryptographic Failures

**What we detect**:
- Weak hashing algorithms (MD5, SHA1)
- Hardcoded encryption keys
- Insecure random number generation
- Missing SSL/TLS
- Vulnerable TLS versions

**Example**:
```javascript
// Vulnerable
const hash = crypto.createHash('md5');
const key = "hardcoded_key_123";
```

### A03:2021 - Injection

**What we detect**:
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- Expression Language Injection

**Example**:
```javascript
// SQL Injection
const query = `SELECT * FROM users WHERE id = ${userId}`;

// Command Injection
exec(`ping ${userInput}`);

// NoSQL Injection
db.users.find({ username: req.body.username });
```

### A04:2021 - Insecure Design

**What we detect**:
- Missing security controls
- Inadequate input validation
- Business logic flaws

### A05:2021 - Security Misconfiguration

**What we detect**:
- Default credentials
- Unnecessary features enabled
- Improper error handling
- Missing security headers
- IaC misconfigurations

**Example**:
```javascript
// Verbose error messages
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack }); // Leaks internals
});
```

### A06:2021 - Vulnerable and Outdated Components

**What we detect**:
- Known CVEs in dependencies
- Outdated packages
- Vulnerable frameworks

**Detection method**:
- npm audit integration
- CVE database lookup
- Version checking

### A07:2021 - Identification and Authentication Failures

**What we detect**:
- Hardcoded credentials
- Weak password policies
- Insecure session management
- Missing MFA
- JWT misconfigurations

**Example**:
```javascript
// Hardcoded credentials
const dbPassword = "admin123";

// Weak JWT
jwt.sign(payload, 'weak_secret', { algorithm: 'none' });

// Insecure cookies
res.cookie('session', token); // Missing httpOnly, secure flags
```

### A08:2021 - Software and Data Integrity Failures

**What we detect**:
- Missing integrity checks
- Insecure deserialization
- Unverified updates

**Example**:
```python
# Insecure deserialization
import pickle
data = pickle.loads(user_input)
```

### A09:2021 - Security Logging and Monitoring Failures

**What we detect**:
- Missing audit logs
- Insufficient monitoring
- Log injection

### A10:2021 - Server-Side Request Forgery (SSRF)

**What we detect**:
- Unvalidated URLs
- Internal network access
- Cloud metadata access

**Example**:
```javascript
// SSRF
const url = req.query.url;
axios.get(url); // No validation
```

## CWE Mappings

### CWE-78: OS Command Injection

```javascript
// Vulnerable
child_process.exec(`git clone ${repo_url}`);

// Secure
child_process.execFile('git', ['clone', repo_url]);
```

### CWE-79: Cross-Site Scripting (XSS)

```javascript
// Vulnerable
element.innerHTML = userInput;

// Secure
element.textContent = userInput;
```

### CWE-89: SQL Injection

```javascript
// Vulnerable
db.query(`SELECT * FROM users WHERE id = ${id}`);

// Secure
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

### CWE-200: Information Exposure

```javascript
// Vulnerable
console.log(error.stack);
res.json({ error: error.message, stack: error.stack });

// Secure
logger.error(error);
res.json({ error: 'Internal server error' });
```

### CWE-259: Hard-coded Password

```javascript
// Vulnerable
const password = "admin123";

// Secure
const password = process.env.DB_PASSWORD;
```

### CWE-327: Broken Cryptography

```javascript
// Vulnerable
crypto.createHash('md5');

// Secure
crypto.createHash('sha256');
```

### CWE-352: Cross-Site Request Forgery (CSRF)

```javascript
// Vulnerable
app.post('/transfer', (req, res) => {
  transfer(req.body.amount);
});

// Secure
app.use(csrf());
app.post('/transfer', csrfProtection, (req, res) => {
  transfer(req.body.amount);
});
```

### CWE-434: Unrestricted Upload

```javascript
// Vulnerable
app.post('/upload', (req, res) => {
  const file = req.files.upload;
  file.mv(`./uploads/${file.name}`);
});

// Secure
const allowedTypes = ['image/jpeg', 'image/png'];
if (!allowedTypes.includes(file.mimetype)) {
  return res.status(400).send('Invalid file type');
}
```

### CWE-502: Deserialization of Untrusted Data

```javascript
// Vulnerable
const obj = JSON.parse(userInput);
eval(userInput);

// Secure
const obj = JSON.parse(userInput);
// Validate obj structure before use
```

### CWE-611: XML External Entity (XXE)

```javascript
// Vulnerable
const parser = new xml2js.Parser();
parser.parseString(xmlInput);

// Secure
const parser = new xml2js.Parser({
  explicitArray: false,
  xmlns: false
});
```

### CWE-798: Hard-coded Credentials

```javascript
// Vulnerable
const apiKey = "sk_live_1234567890";

// Secure
const apiKey = process.env.API_KEY;
```

### CWE-829: Inclusion of Functionality from Untrusted Control Sphere

```javascript
// Vulnerable
const module = require(userProvidedPath);

// Secure
const allowedModules = ['lodash', 'axios'];
if (allowedModules.includes(moduleName)) {
  const module = require(moduleName);
}
```

## Severity Definitions

### 🔴 Critical

**CVSS 9.0-10.0**

Immediate action required:
- Remote code execution
- Authentication bypass
- Exposed credentials
- Data breach potential

**Response time**: Fix immediately (< 24 hours)

### 🟠 High

**CVSS 7.0-8.9**

Urgent action needed:
- SQL/NoSQL Injection
- XSS vulnerabilities
- Privilege escalation
- Sensitive data exposure

**Response time**: Fix within 1 week

### 🟡 Medium

**CVSS 4.0-6.9**

Should be addressed:
- Information disclosure
- Weak cryptography
- Missing security headers
- Session issues

**Response time**: Fix within 1 month

### 🟢 Low

**CVSS 0.1-3.9**

Recommended fixes:
- Best practice violations
- Defense in depth improvements
- Informational findings

**Response time**: Fix in next release

## Common Patterns

### Secret Detection Patterns

```regex
AWS Access Key: AKIA[0-9A-Z]{16}
Google API Key: AIza[0-9A-Za-z-_]{35}
GitHub Token: ghp_[0-9a-zA-Z]{36}
Slack Token: xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}
```

### Injection Patterns

```javascript
// SQL Injection indicators
"SELECT * FROM " + table
`SELECT * FROM ${table}`
"WHERE id = " + userId

// Command Injection indicators
exec(userInput)
spawn(userInput)
system(userInput)
```

### XSS Patterns

```javascript
// Dangerous assignments
element.innerHTML = userInput
element.outerHTML = userInput
$().html(userInput)

// Dangerous functions
eval(userInput)
Function(userInput)
document.write(userInput)
```

## Next Steps

- [Configuration](./configuration.md) - Customize detection rules
- [API Reference](./api.md) - Programmatic usage
- [Code Scanning](../features/code-scanning.md) - Learn detection details
