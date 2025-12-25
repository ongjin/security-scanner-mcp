#!/usr/bin/env node
/**
 * Security Scanner MCP Server
 *
 * AI가 생성한 코드의 보안 취약점을 자동으로 검출하는 MCP 서버입니다.
 * OWASP Top 10, 하드코딩된 시크릿, 의존성 취약점 등을 검사합니다.
 *
 * @author zerry
 * @license MIT
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as z from 'zod';
import { scanSecrets } from './scanners/secrets.js';
import { scanInjection } from './scanners/injection.js';
import { scanXss } from './scanners/xss.js';
import { scanDependencies } from './scanners/dependencies.js';
import { scanCrypto } from './scanners/crypto.js';
import { scanAuth } from './scanners/auth.js';
import { scanPath } from './scanners/path.js';
import { SecurityIssue, ScanResult, Severity } from './types.js';

// ============================================
// MCP 서버 초기화
// ============================================
const server = new McpServer({
    name: 'security-scanner',
    version: '1.0.0',
});

/**
 * 전체 보안 스캔 실행
 *
 * 코드 조각이나 파일 경로를 받아서 모든 보안 검사를 수행합니다.
 * 하드코딩된 시크릿, SQL Injection, XSS 등을 종합적으로 검사해요.
 */
server.registerTool(
    'scan-security',
    {
        title: '보안 취약점 스캔',
        description: '코드에서 보안 취약점을 검사합니다 (시크릿, SQL Injection, XSS 등)',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto')
                .describe('프로그래밍 언어 (auto면 자동 감지)'),
            context: z.string().optional().describe('추가 컨텍스트 (예: "API 엔드포인트 코드")'),
        },
    },
    async ({ code, language, context }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues: SecurityIssue[] = [];

        // 각종 보안 스캐너 실행 (OWASP Top 10 기반)
        issues.push(...scanSecrets(code));           // 하드코딩된 시크릿
        issues.push(...scanInjection(code, detectedLang));  // SQL/Command Injection
        issues.push(...scanXss(code, detectedLang));        // XSS
        issues.push(...scanCrypto(code, detectedLang));     // 암호화 취약점
        issues.push(...scanAuth(code, detectedLang));       // 인증/세션 취약점
        issues.push(...scanPath(code, detectedLang));       // 파일/경로 취약점

        // 결과 정리
        const result = formatScanResult(issues, code, context);
        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * 하드코딩된 시크릿 검사
 *
 * API 키, 비밀번호, 토큰 등이 코드에 직접 박혀있는지 검사합니다.
 * 이거 진짜 많이 실수하는 부분이에요... 저도 가끔 깜빡하고 커밋했다가 식겁한 적 있음 ㅋㅋ
 */
server.registerTool(
    'scan-secrets',
    {
        title: '하드코딩된 시크릿 검사',
        description: 'API 키, 비밀번호, 토큰 등 민감한 정보가 코드에 노출되어 있는지 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
        },
    },
    async ({ code }) => {
        const issues = scanSecrets(code);
        const result = formatSecretScanResult(issues, code);
        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * SQL Injection 취약점 검사
 *
 * 사용자 입력이 SQL 쿼리에 직접 들어가는 위험한 패턴을 찾습니다.
 * prepared statement 안 쓰면 진짜 큰일나요...
 */
server.registerTool(
    'scan-injection',
    {
        title: 'SQL Injection 검사',
        description: 'SQL Injection 취약점이 있는지 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto'),
        },
    },
    async ({ code, language }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues = scanInjection(code, detectedLang);
        const result = formatInjectionScanResult(issues, code);
        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * XSS 취약점 검사
 *
 * 사용자 입력이 이스케이프 없이 HTML에 들어가는 패턴을 찾습니다.
 * React는 기본적으로 안전하지만 dangerouslySetInnerHTML 쓰면...
 */
server.registerTool(
    'scan-xss',
    {
        title: 'XSS 취약점 검사',
        description: 'Cross-Site Scripting 취약점이 있는지 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto'),
        },
    },
    async ({ code, language }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues = scanXss(code, detectedLang);
        const result = formatXssScanResult(issues, code);
        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * 의존성 취약점 검사
 *
 * package.json이나 requirements.txt를 분석해서 알려진 취약점이 있는 패키지를 찾습니다.
 * npm audit이나 pip-audit 같은 역할이에요.
 */
server.registerTool(
    'scan-dependencies',
    {
        title: '의존성 취약점 검사',
        description: 'package.json, requirements.txt 등에서 취약한 의존성 검사',
        inputSchema: {
            projectPath: z.string().describe('프로젝트 루트 경로'),
        },
    },
    async ({ projectPath }) => {
        const issues = await scanDependencies(projectPath);
        const result = formatDependencyScanResult(issues);
        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * 암호화 관련 취약점 검사
 *
 * 약한 해시, 안전하지 않은 랜덤, 하드코딩된 암호화 키 등을 검사합니다.
 */
server.registerTool(
    'scan-crypto',
    {
        title: '암호화 취약점 검사',
        description: '약한 해시, 안전하지 않은 랜덤, SSL/TLS 설정 등 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto'),
        },
    },
    async ({ code, language }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues = scanCrypto(code, detectedLang);
        return { content: [{ type: 'text', text: formatCryptoScanResult(issues) }] };
    }
);

/**
 * 인증/세션 취약점 검사
 *
 * JWT 설정, 세션 관리, CORS 설정 등을 검사합니다.
 */
server.registerTool(
    'scan-auth',
    {
        title: '인증/세션 취약점 검사',
        description: 'JWT, 세션, CORS, 쿠키 설정 등 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto'),
        },
    },
    async ({ code, language }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues = scanAuth(code, detectedLang);
        return { content: [{ type: 'text', text: formatAuthScanResult(issues) }] };
    }
);

/**
 * 파일/경로 취약점 검사
 *
 * Path Traversal, 위험한 파일 작업, 파일 업로드 취약점 등을 검사합니다.
 */
server.registerTool(
    'scan-path',
    {
        title: '파일/경로 취약점 검사',
        description: 'Path Traversal, 파일 업로드, 경로 조작 등 검사',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto'),
        },
    },
    async ({ code, language }) => {
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;
        const issues = scanPath(code, detectedLang);
        return { content: [{ type: 'text', text: formatPathScanResult(issues) }] };
    }
);

// ============================================
// 유틸리티 함수들
// ============================================

/**
 * 코드에서 언어를 자동 감지
 * 완벽하진 않지만 대부분의 경우 잘 동작해요
 */
function detectLanguage(code: string): string {
    if (code.includes('import React') || code.includes('useState')) return 'javascript';
    if (code.includes(': string') || code.includes(': number')) return 'typescript';
    if (code.includes('def ') || code.includes('import ')) return 'python';
    if (code.includes('public class') || code.includes('private void')) return 'java';
    if (code.includes('func ') || code.includes('package main')) return 'go';
    return 'javascript'; // 기본값
}

/**
 * 전체 스캔 결과 포맷팅
 */
function formatScanResult(issues: SecurityIssue[], code: string, context?: string): string {
    if (issues.length === 0) {
        return `## ✅ 보안 검사 통과!

이 코드에서 발견된 보안 취약점이 없습니다.

${context ? `> 컨텍스트: ${context}` : ''}

하지만 자동 검사로 모든 취약점을 찾을 수는 없어요.
중요한 코드는 수동 보안 리뷰도 권장합니다.`;
    }

    const critical = issues.filter(i => i.severity === 'critical');
    const high = issues.filter(i => i.severity === 'high');
    const medium = issues.filter(i => i.severity === 'medium');
    const low = issues.filter(i => i.severity === 'low');

    let result = `## ⚠️ 보안 취약점 발견!

총 **${issues.length}개**의 취약점이 발견되었습니다.

`;

    if (critical.length > 0) {
        result += `### 🔴 Critical (${critical.length}개)\n`;
        result += formatIssueList(critical);
    }

    if (high.length > 0) {
        result += `### 🟠 High (${high.length}개)\n`;
        result += formatIssueList(high);
    }

    if (medium.length > 0) {
        result += `### 🟡 Medium (${medium.length}개)\n`;
        result += formatIssueList(medium);
    }

    if (low.length > 0) {
        result += `### 🟢 Low (${low.length}개)\n`;
        result += formatIssueList(low);
    }

    result += `\n---\n\n**이 취약점들을 수정한 후 다시 검사해주세요!**`;

    return result;
}

function formatIssueList(issues: SecurityIssue[]): string {
    return issues.map(issue => `
- **${issue.type}** (라인 ${issue.line || '?'})
  - ${issue.message}
  - 💡 해결책: ${issue.fix}
`).join('') + '\n';
}

function formatSecretScanResult(issues: SecurityIssue[], code: string): string {
    if (issues.length === 0) {
        return `## ✅ 하드코딩된 시크릿 없음!

코드에서 API 키, 비밀번호, 토큰 등이 발견되지 않았습니다.
환경 변수를 잘 사용하고 계시네요! 👍`;
    }

    return `## 🚨 하드코딩된 시크릿 발견!

**${issues.length}개**의 민감한 정보가 코드에 노출되어 있습니다.

${issues.map(issue => `
### ${issue.severity === 'critical' ? '🔴' : '🟠'} ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **내용**: \`${issue.match?.slice(0, 20)}...\`
- **문제**: ${issue.message}
- **해결책**: ${issue.fix}
`).join('\n')}

---

⚠️ **절대로 이 코드를 커밋하지 마세요!**
시크릿은 환경 변수나 시크릿 매니저를 사용해주세요.`;
}

function formatInjectionScanResult(issues: SecurityIssue[], code: string): string {
    if (issues.length === 0) {
        return `## ✅ SQL Injection 취약점 없음!

안전한 쿼리 패턴을 사용하고 계시네요.
Prepared Statement, ORM 등을 잘 활용하고 계십니다! 👍`;
    }

    return `## 🚨 SQL Injection 취약점 발견!

**${issues.length}개**의 잠재적 SQL Injection 포인트가 있습니다.

${issues.map(issue => `
### 🔴 ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **문제**: ${issue.message}
- **위험**: 공격자가 임의의 SQL을 실행할 수 있습니다
- **해결책**: ${issue.fix}
`).join('\n')}

---

📚 **참고**: OWASP SQL Injection Prevention Cheat Sheet`;
}

function formatXssScanResult(issues: SecurityIssue[], code: string): string {
    if (issues.length === 0) {
        return `## ✅ XSS 취약점 없음!

사용자 입력을 안전하게 처리하고 계십니다! 👍`;
    }

    return `## 🚨 XSS 취약점 발견!

**${issues.length}개**의 잠재적 XSS 포인트가 있습니다.

${issues.map(issue => `
### 🔴 ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **문제**: ${issue.message}
- **위험**: 공격자가 악성 스크립트를 실행할 수 있습니다
- **해결책**: ${issue.fix}
`).join('\n')}`;
}

function formatDependencyScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ 의존성 취약점 없음!

사용 중인 패키지들에 알려진 취약점이 없습니다! 👍`;
    }

    return `## 🚨 취약한 의존성 발견!

**${issues.length}개**의 취약한 패키지가 있습니다.

${issues.map(issue => `
### ${issue.severity === 'critical' ? '🔴' : issue.severity === 'high' ? '🟠' : '🟡'} ${issue.type}
- **패키지**: ${issue.match}
- **문제**: ${issue.message}
- **해결책**: ${issue.fix}
`).join('\n')}

\`npm audit fix\` 또는 \`npm update\`를 실행해보세요.`;
}

function formatCryptoScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ 암호화 취약점 없음!

안전한 암호화 패턴을 사용하고 계시네요! 👍`;
    }

    return `## 🚨 암호화 취약점 발견!

**${issues.length}개**의 암호화 관련 취약점이 있습니다.

${issues.map(issue => `
### ${issue.severity === 'critical' ? '🔴' : issue.severity === 'high' ? '🟠' : '🟡'} ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **문제**: ${issue.message}
- **해결책**: ${issue.fix}
`).join('\n')}`;
}

function formatAuthScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ 인증/세션 취약점 없음!

인증 관련 설정이 안전해 보입니다! 👍`;
    }

    return `## 🚨 인증/세션 취약점 발견!

**${issues.length}개**의 인증 관련 취약점이 있습니다.

${issues.map(issue => `
### ${issue.severity === 'critical' ? '🔴' : issue.severity === 'high' ? '🟠' : '🟡'} ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **문제**: ${issue.message}
- **해결책**: ${issue.fix}
`).join('\n')}`;
}

function formatPathScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ 파일/경로 취약점 없음!

파일 처리가 안전해 보입니다! 👍`;
    }

    return `## 🚨 파일/경로 취약점 발견!

**${issues.length}개**의 파일/경로 관련 취약점이 있습니다.

${issues.map(issue => `
### ${issue.severity === 'critical' ? '🔴' : issue.severity === 'high' ? '🟠' : '🟡'} ${issue.type}
- **위치**: 라인 ${issue.line || '?'}
- **문제**: ${issue.message}
- **해결책**: ${issue.fix}
`).join('\n')}`;
}

// ============================================
// 서버 시작
// ============================================
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);

    // stderr로 로그 출력 (stdout은 MCP 통신용)
    console.error('🔒 Security Scanner MCP Server 시작됨!');
    console.error('   by zerry');
}

main().catch(console.error);
