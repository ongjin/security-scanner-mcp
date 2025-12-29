---
sidebar_position: 2
---

# 설정 참조

Security Scanner MCP의 완전한 설정 가이드.

## 설정 파일

### .securityscannerrc

프로젝트 루트에 생성:

```json
{
  "version": "1.0",
  "exclude": [
    "node_modules/**",
    "dist/**",
    "*.test.js"
  ],
  "severity": {
    "minLevel": "medium",
    "failOn": ["critical", "high"]
  },
  "rules": {
    "secrets": {
      "enabled": true
    },
    "injection": {
      "enabled": true,
      "sql": true,
      "command": true
    }
  }
}
```

## 환경 변수

### 스캐너 설정

```bash
export SCANNER_VERBOSE=true
export SCANNER_OUTPUT=json
export SCANNER_MIN_SEVERITY=high
```

### 샌드박스 설정

```bash
export SANDBOX_MEMORY=1g
export SANDBOX_CPU=1.0
export SANDBOX_TIMEOUT=60000
```

## MCP 서버 설정

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` 편집:

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

## 규칙 설정

### 규칙 활성화/비활성화

```json
{
  "rules": {
    "secrets": true,
    "injection": false,
    "xss": {
      "enabled": true,
      "detectInnerHTML": true
    }
  }
}
```

## 다음 단계

- [API 참조](./api.md) - 프로그래밍 방식 설정
- [통합](../advanced/integration.md) - CI/CD 설정
