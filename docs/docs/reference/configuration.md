---
sidebar_position: 2
---

# Configuration Reference

Complete configuration guide for Security Scanner MCP.

## Configuration Files

### .securityscannerrc

Create in project root:

```json
{
  "version": "1.0",
  "exclude": [
    "node_modules/**",
    "dist/**",
    "build/**",
    "*.test.js",
    "*.spec.ts"
  ],
  "include": [
    "src/**/*.js",
    "src/**/*.ts",
    "lib/**/*.py"
  ],
  "severity": {
    "minLevel": "medium",
    "failOn": ["critical", "high"]
  },
  "rules": {
    "secrets": {
      "enabled": true,
      "patterns": "default"
    },
    "injection": {
      "enabled": true,
      "sql": true,
      "nosql": true,
      "command": true
    },
    "xss": {
      "enabled": true,
      "strictMode": false
    },
    "crypto": {
      "enabled": true,
      "allowedAlgorithms": ["sha256", "sha512", "bcrypt"]
    },
    "auth": {
      "enabled": true,
      "enforceHttpOnly": true,
      "enforceSecure": true
    },
    "path": {
      "enabled": true,
      "checkTraversal": true
    }
  },
  "output": {
    "format": "json",
    "verbose": false,
    "colors": true
  }
}
```

### Package.json Integration

```json
{
  "securityScanner": {
    "exclude": ["test/**"],
    "severity": {
      "minLevel": "high"
    }
  }
}
```

## Rule Configuration

### Enable/Disable Rules

```json
{
  "rules": {
    "secrets": true,      // Enable
    "injection": false,   // Disable
    "xss": {              // Detailed config
      "enabled": true,
      "detectInnerHTML": true,
      "detectEval": true,
      "detectDocumentWrite": false
    }
  }
}
```

### Custom Severity Levels

```json
{
  "severity": {
    "minLevel": "medium",
    "custom": {
      "sql-injection": "critical",
      "xss-innerHTML": "high",
      "weak-crypto": "medium"
    }
  }
}
```

### Custom Patterns

```json
{
  "customPatterns": {
    "secrets": [
      {
        "name": "Custom API Key",
        "pattern": "custom_api_[0-9a-z]{32}",
        "severity": "critical"
      }
    ],
    "injection": [
      {
        "name": "GraphQL Injection",
        "pattern": "\\$\\{.*query.*\\}",
        "severity": "high"
      }
    ]
  }
}
```

## Environment Variables

### Scanner Configuration

```bash
# Verbosity
export SCANNER_VERBOSE=true
export SCANNER_DEBUG=false

# Output format
export SCANNER_OUTPUT=json  # json | text | sarif

# Severity filtering
export SCANNER_MIN_SEVERITY=high

# Performance
export SCANNER_PARALLEL=true
export SCANNER_MAX_FILES=1000
```

### Sandbox Configuration

```bash
# Docker settings
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# Network
export SANDBOX_NETWORK=none

# Tool versions
export TRIVY_VERSION=0.50.4
export GITLEAKS_VERSION=8.18.4
```

## MCP Server Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "security-scanner-mcp",
      "args": [],
      "env": {
        "SCANNER_MIN_SEVERITY": "high"
      }
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add --scope project security-scanner \
  -- security-scanner-mcp \
  --env SCANNER_VERBOSE=true \
  --env SCANNER_MIN_SEVERITY=medium
```

## Ignore Patterns

### Inline Ignores

```javascript
// security-scanner-ignore
const apiKey = "test_key_for_development";

// security-scanner-ignore-next-line
const query = `SELECT * FROM ${table}`;

/* security-scanner-disable */
const unsafe = eval(userInput);
/* security-scanner-enable */
```

### File-level Ignores

```javascript
// security-scanner-disable-file
// This file is excluded from scanning
```

### .securityscannerignore

```.gitignore
# Test files
*.test.js
*.spec.ts

# Generated files
**/*.generated.js

# Third-party
vendor/**
```

## Output Configuration

### Format Options

```json
{
  "output": {
    "format": "json",        // json | text | sarif | html
    "destination": "stdout", // stdout | file
    "file": "security-report.json",
    "pretty": true,
    "includeMetadata": true
  }
}
```

### Report Templates

```json
{
  "reporting": {
    "template": "default",    // default | minimal | detailed
    "sections": {
      "summary": true,
      "diagrams": true,
      "sarif": true,
      "recommendations": true
    },
    "mermaid": {
      "enabled": true,
      "theme": "default"
    }
  }
}
```

## Performance Tuning

### Parallel Scanning

```json
{
  "performance": {
    "parallel": true,
    "maxWorkers": 4,
    "chunkSize": 100
  }
}
```

### Caching

```json
{
  "cache": {
    "enabled": true,
    "ttl": 3600,
    "directory": ".scanner-cache"
  }
}
```

### Resource Limits

```json
{
  "limits": {
    "maxFileSize": "10MB",
    "maxLines": 10000,
    "timeout": 30000
  }
}
```

## Integration Settings

### CI/CD

```json
{
  "ci": {
    "failOnError": true,
    "failOnSeverity": ["critical", "high"],
    "outputFormat": "sarif",
    "uploadResults": true
  }
}
```

### GitHub Integration

```json
{
  "github": {
    "enableCodeScanning": true,
    "sarifUpload": true,
    "annotations": true,
    "commentOnPR": false
  }
}
```

## Language-Specific Settings

### JavaScript/TypeScript

```json
{
  "languages": {
    "javascript": {
      "strictMode": true,
      "checkNodeModules": false,
      "frameworks": ["react", "vue", "angular"]
    },
    "typescript": {
      "strictMode": true,
      "checkTypes": true
    }
  }
}
```

### Python

```json
{
  "languages": {
    "python": {
      "version": "3.x",
      "checkPickle": true,
      "checkEval": true
    }
  }
}
```

## Advanced Configuration

### Custom Validators

```javascript
// custom-validator.js
module.exports = {
  validate(code, language) {
    // Custom validation logic
    return issues;
  }
};
```

```json
{
  "customValidators": [
    "./custom-validator.js"
  ]
}
```

### Plugin System

```json
{
  "plugins": [
    "@security-scanner/plugin-graphql",
    "@security-scanner/plugin-kubernetes"
  ]
}
```

## Configuration Precedence

1. CLI arguments (highest priority)
2. Environment variables
3. `.securityscannerrc`
4. `package.json` securityScanner field
5. Default settings (lowest priority)

## Examples

### Strict Configuration

```json
{
  "severity": {
    "minLevel": "low",
    "failOn": ["critical", "high", "medium"]
  },
  "rules": {
    "*": {
      "enabled": true,
      "strictMode": true
    }
  },
  "output": {
    "verbose": true
  }
}
```

### Permissive Configuration

```json
{
  "severity": {
    "minLevel": "critical",
    "failOn": ["critical"]
  },
  "rules": {
    "secrets": true,
    "injection": true,
    "xss": false,
    "crypto": false
  }
}
```

## Next Steps

- [API Reference](./api.md) - Programmatic configuration
- [Integration](../advanced/integration.md) - CI/CD setup
- [Vulnerabilities](./vulnerabilities.md) - Rule details
