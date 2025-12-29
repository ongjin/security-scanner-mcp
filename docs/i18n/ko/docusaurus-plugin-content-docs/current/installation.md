---
sidebar_position: 2
---

# 설치

Security Scanner MCP를 프로젝트에 설치하고 설정하는 방법을 알아보세요.

## 전제 조건

시작하기 전에 다음이 설치되어 있는지 확인하세요:

- **Node.js** 18.0.0 이상
- **npm** 또는 **yarn**
- **Claude Desktop** 또는 **Claude Code CLI**

## 설치 방법

### npm을 사용한 설치

```bash
npm install -g security-scanner-mcp
```

### yarn을 사용한 설치

```bash
yarn global add security-scanner-mcp
```

### 소스에서 설치

```bash
git clone https://github.com/ongjin/security-scanner-mcp.git
cd security-scanner-mcp
npm install
npm run build
npm link
```

## MCP 서버 설정

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) 또는  
`%APPDATA%/Claude/claude_desktop_config.json` (Windows) 파일을 편집하세요:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "security-scanner-mcp",
      "args": []
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add security-scanner -- security-scanner-mcp
```

또는 프로젝트별 설정:

```bash
claude mcp add --scope project security-scanner -- security-scanner-mcp
```

## 설치 확인

### 직접 테스트

```bash
security-scanner-mcp --version
```

### MCP 서버가 실행 중인지 확인

Claude Desktop 또는 Claude Code에서:

```
안녕, Claude! 사용 가능한 MCP 서버를 보여줘.
```

"security-scanner"가 목록에 표시되어야 합니다.

### 간단한 스캔 테스트

```
이 코드를 스캔해줘:

const apiKey = "AIzaSyC1234567890";
```

Claude가 하드코딩된 API 키를 탐지하고 보고해야 합니다.

## Docker 샌드박스 설정 (선택사항)

격리된 환경에서 스캔하려면:

```bash
docker pull ongjin/security-scanner-mcp:latest
docker tag ongjin/security-scanner-mcp:latest security-scanner-mcp:latest
```

자세한 내용은 [Docker 샌드박스 스캔](./features/sandbox.md)을 참조하세요.

## 환경 변수

선택적 설정을 위한 환경 변수:

```bash
# 스캐너 설정
export SCANNER_VERBOSE=true      # 상세 출력 활성화
export SCANNER_MIN_SEVERITY=high # 최소 심각도 수준

# 샌드박스 설정 (Docker)
export SANDBOX_MEMORY=1g         # 메모리 제한
export SANDBOX_CPU=1.0           # CPU 제한
export SANDBOX_TIMEOUT=60000     # 타임아웃(밀리초)
```

## 문제 해결

### MCP 서버를 찾을 수 없음

```bash
# 설치 확인
which security-scanner-mcp

# 설치되지 않은 경우 재설치
npm install -g security-scanner-mcp
```

### 권한 오류

```bash
# macOS/Linux
sudo npm install -g security-scanner-mcp

# 또는 npm 글로벌 디렉토리 권한 수정
sudo chown -R $USER /usr/local/lib/node_modules
```

### Claude Desktop이 MCP 서버를 로드하지 않음

1. Claude Desktop 완전히 종료
2. 설정 파일에 JSON 구문 오류가 없는지 확인
3. Claude Desktop 재시작
4. 로그 확인: `~/Library/Logs/Claude/mcp.log`

## 다음 단계

- [빠른 시작](./quick-start.md) - 첫 스캔 실행
- [기본 사용법](./usage/basic-usage.md) - 모든 기능 배우기
- [설정](./reference/configuration.md) - 동작 사용자 정의
