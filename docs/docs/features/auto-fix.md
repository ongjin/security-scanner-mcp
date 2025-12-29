---
sidebar_position: 3
---

# Auto-Fix Suggestions

Get AI-generated code fixes for detected vulnerabilities.

## How It Works

The `get-fix-suggestion` tool provides:
1. **Before/After code comparison**
2. **Explanation of the vulnerability**
3. **Step-by-step remediation**
4. **Alternative solutions** (when applicable)

## Supported Vulnerability Types

### Hardcoded Secrets

```typescript
// Original (vulnerable)
const apiKey = "AIzaSyC1234567890abcdef";

// Fixed
const apiKey = process.env.GOOGLE_API_KEY;

// Additional recommendations:
// 1. Add API key to .env file
// 2. Add .env to .gitignore
// 3. Use API key restrictions in Google Cloud Console
```

### SQL Injection

```javascript
// Original (vulnerable)
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// Fixed - Prepared statements
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

// Alternative - ORM
const user = await User.findByPk(userId);
```

### XSS Vulnerabilities

```javascript
// Original (vulnerable)
element.innerHTML = userInput;

// Fixed - Option 1: Text content
element.textContent = userInput;

// Fixed - Option 2: DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Weak Cryptography

```javascript
// Original (vulnerable)
const hash = crypto.createHash('md5').update(password).digest('hex');

// Fixed
const hash = await bcrypt.hash(password, 10);

// Or for general hashing
const hash = crypto.createHash('sha256').update(data).digest('hex');
```

### Insecure Authentication

```javascript
// Original (vulnerable)
res.cookie('session', sessionId);

// Fixed
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 3600000 // 1 hour
});
```

### Path Traversal

```javascript
// Original (vulnerable)
const file = fs.readFileSync(userPath);

// Fixed
const path = require('path');
const safePath = path.join(__dirname, 'uploads', path.basename(userPath));

// Verify path is within allowed directory
if (!safePath.startsWith(path.join(__dirname, 'uploads'))) {
  throw new Error('Invalid path');
}

const file = fs.readFileSync(safePath);
```

## Usage

### Get Fix for Specific Issue

```
Me: How do I fix this SQL injection vulnerability?

const query = `SELECT * FROM users WHERE email = '${email}'`;
```

### Get Fix After Scanning

```
Me: Scan this code and show me how to fix the issues

[paste code]

Claude: [Runs scan, finds issues]

Me: Show me how to fix the XSS vulnerability

Claude: [Calls get-fix-suggestion]
```

## AST-Based Code Transformation

For certain vulnerabilities, the tool uses Abstract Syntax Tree (AST) analysis to provide precise fixes:

- Exact line and column numbers
- Context-aware suggestions
- Maintains code formatting
- Preserves comments

## Best Practices

1. **Review before applying**: Understand the fix before implementing
2. **Test thoroughly**: Verify the fix doesn't break functionality
3. **Consider alternatives**: Choose the best solution for your use case
4. **Update dependencies**: Sometimes the fix requires new packages
5. **Document changes**: Add comments explaining security improvements

## Limitations

- Cannot fix all vulnerabilities automatically
- Some issues require architectural changes
- Human review is always recommended
- Context-specific fixes may need adjustment

## Advanced Usage

### Request Multiple Fix Options

```
Me: Show me different ways to fix this authentication issue
```

### Get Explanation with Fix

```
Me: Explain why this is vulnerable and how to fix it
```

### Framework-Specific Fixes

```
Me: How would I fix this in React/Vue/Angular?
```

## Next Steps

- [Code Scanning](./code-scanning.md) - Learn about vulnerability detection
- [IaC Scanning](./iac-scanning.md) - Fix infrastructure misconfigurations
- [Reporting](../advanced/reporting.md) - Generate comprehensive reports
