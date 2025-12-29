---
sidebar_position: 2
---

# 配置参考

Security Scanner MCP 的完整配置指南。

## 配置文件

### .securityscannerrc

在项目根目录创建：

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

### Package.json 集成

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

## 规则配置

### 启用/禁用规则

```json
{
  "rules": {
    "secrets": true,      // 启用
    "injection": false,   // 禁用
    "xss": {              // 详细配置
      "enabled": true,
      "detectInnerHTML": true,
      "detectEval": true,
      "detectDocumentWrite": false
    }
  }
}
```

### 自定义严重程度级别

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

### 自定义模式

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

## 环境变量

### 扫描工具配置

```bash
# 详细程度
export SCANNER_VERBOSE=true
export SCANNER_DEBUG=false

# 输出格式
export SCANNER_OUTPUT=json  # json | text | sarif

# 严重程度过滤
export SCANNER_MIN_SEVERITY=high

# 性能
export SCANNER_PARALLEL=true
export SCANNER_MAX_FILES=1000
```

### 沙箱配置

```bash
# Docker 设置
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# 网络
export SANDBOX_NETWORK=none

# 工具版本
export TRIVY_VERSION=0.50.4
export GITLEAKS_VERSION=8.18.4
```

## MCP 服务器配置

### Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`：

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

## 忽略模式

### 内联忽略

```javascript
// security-scanner-ignore
const apiKey = "test_key_for_development";

// security-scanner-ignore-next-line
const query = `SELECT * FROM ${table}`;

/* security-scanner-disable */
const unsafe = eval(userInput);
/* security-scanner-enable */
```

### 文件级忽略

```javascript
// security-scanner-disable-file
// 此文件从扫描中排除
```

### .securityscannerignore

```
# 测试文件
*.test.js
*.spec.ts

# 生成的文件
**/*.generated.js

# 第三方
vendor/**
```

## 输出配置

### 格式选项

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

### 报告模板

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

## 性能调整

### 并行扫描

```json
{
  "performance": {
    "parallel": true,
    "maxWorkers": 4,
    "chunkSize": 100
  }
}
```

### 缓存

```json
{
  "cache": {
    "enabled": true,
    "ttl": 3600,
    "directory": ".scanner-cache"
  }
}
```

### 资源限制

```json
{
  "limits": {
    "maxFileSize": "10MB",
    "maxLines": 10000,
    "timeout": 30000
  }
}
```

## 集成设置

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

### GitHub 集成

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

## 语言特定设置

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

## 高级配置

### 自定义验证器

```javascript
// custom-validator.js
module.exports = {
  validate(code, language) {
    // 自定义验证逻辑
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

### 插件系统

```json
{
  "plugins": [
    "@security-scanner/plugin-graphql",
    "@security-scanner/plugin-kubernetes"
  ]
}
```

## 配置优先级

1. CLI 参数（最高优先级）
2. 环境变量
3. `.securityscannerrc`
4. `package.json` securityScanner 字段
5. 默认设置（最低优先级）

## 示例

### 严格配置

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

### 宽松配置

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

## 下一步

- [API 参考](./api.md) - 编程配置
- [集成](../advanced/integration.md) - CI/CD 设置
- [漏洞](./vulnerabilities.md) - 规则详情
