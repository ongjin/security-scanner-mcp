---
sidebar_position: 2
---

# 設定リファレンス

Security Scanner MCPの完全な設定ガイド。

## 設定ファイル

### .securityscannerrc

プロジェクトルートに作成:

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

### Package.json 統合

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

## ルール設定

### ルールを有効/無効化

```json
{
  "rules": {
    "secrets": true,      // 有効化
    "injection": false,   // 無効化
    "xss": {              // 詳細設定
      "enabled": true,
      "detectInnerHTML": true,
      "detectEval": true,
      "detectDocumentWrite": false
    }
  }
}
```

### カスタム重大度レベル

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

### カスタムパターン

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

## 環境変数

### スキャナー設定

```bash
# 詳細性
export SCANNER_VERBOSE=true
export SCANNER_DEBUG=false

# 出力フォーマット
export SCANNER_OUTPUT=json  # json | text | sarif

# 重大度フィルタリング
export SCANNER_MIN_SEVERITY=high

# パフォーマンス
export SCANNER_PARALLEL=true
export SCANNER_MAX_FILES=1000
```

### サンドボックス設定

```bash
# Docker設定
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000

# ネットワーク
export SANDBOX_NETWORK=none

# ツールバージョン
export TRIVY_VERSION=0.50.4
export GITLEAKS_VERSION=8.18.4
```

## MCPサーバー設定

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`を編集:

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

## 除外パターン

### インラインで除外

```javascript
// security-scanner-ignore
const apiKey = "test_key_for_development";

// security-scanner-ignore-next-line
const query = `SELECT * FROM ${table}`;

/* security-scanner-disable */
const unsafe = eval(userInput);
/* security-scanner-enable */
```

### ファイルレベルで除外

```javascript
// security-scanner-disable-file
// このファイルはスキャンから除外されます
```

### .securityscannerignore

```.gitignore
# テストファイル
*.test.js
*.spec.ts

# 生成されたファイル
**/*.generated.js

# サードパーティ
vendor/**
```

## 出力設定

### フォーマットオプション

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

### レポートテンプレート

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

## パフォーマンスチューニング

### 並列スキャン

```json
{
  "performance": {
    "parallel": true,
    "maxWorkers": 4,
    "chunkSize": 100
  }
}
```

### キャッシング

```json
{
  "cache": {
    "enabled": true,
    "ttl": 3600,
    "directory": ".scanner-cache"
  }
}
```

### リソース制限

```json
{
  "limits": {
    "maxFileSize": "10MB",
    "maxLines": 10000,
    "timeout": 30000
  }
}
```

## 統合設定

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

### GitHub統合

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

## 言語固有の設定

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

## 高度な設定

### カスタムバリデーター

```javascript
// custom-validator.js
module.exports = {
  validate(code, language) {
    // カスタム検証ロジック
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

### プラグインシステム

```json
{
  "plugins": [
    "@security-scanner/plugin-graphql",
    "@security-scanner/plugin-kubernetes"
  ]
}
```

## 設定の優先順位

1. CLIの引数（最高優先度）
2. 環境変数
3. `.securityscannerrc`
4. `package.json`の securityScannerフィールド
5. デフォルト設定（最低優先度）

## 例

### 厳密な設定

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

### 許容的な設定

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

## 次のステップ

- [APIリファレンス](./api.md) - プログラム的な設定
- [統合](../advanced/integration.md) - CI/CDセットアップ
- [脆弱性](./vulnerabilities.md) - ルール詳細
