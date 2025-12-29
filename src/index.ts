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
import { fixCode, formatFixResult } from './remediation/code-fixer.js';
import { scanIaCFile, detectIaCType, formatIaCScanResult, type IaCType } from './iac-scanners/index.js';
import { cveLookupClient } from './external/cve-lookup.js';
import { getOWASPInfo, getCWEInfo } from './external/owasp-database.js';
import { generateSecurityDashboard } from './reporting/mermaid-generator.js';
import { generateSARIFReport, sarifToJSON } from './reporting/sarif-generator.js';
import { dockerSandboxManager } from './sandbox/docker-manager.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

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

/**
 * 취약점 자동 수정 제안
 *
 * 발견된 취약점에 대한 수정된 코드를 제공합니다.
 */
server.registerTool(
    'get-fix-suggestion',
    {
        title: '취약점 자동 수정 제안',
        description: '발견된 취약점에 대한 수정된 코드 제공',
        inputSchema: {
            code: z.string().describe('원본 코드'),
            issueType: z.string().describe('수정할 취약점 타입 (예: "innerHTML Assignment")'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go'])
                .default('javascript')
                .describe('프로그래밍 언어'),
        },
    },
    async ({ code, issueType, language }) => {
        // 간단한 SecurityIssue 객체 생성
        const mockIssue: SecurityIssue = {
            type: issueType,
            severity: 'high',
            message: '취약점이 발견되었습니다.',
            fix: '코드를 수정하세요.',
        };

        const result = await fixCode(code, mockIssue, language);
        const formatted = formatFixResult(result);

        return { content: [{ type: 'text', text: formatted }] };
    }
);

/**
 * Infrastructure as Code (IaC) 보안 스캔
 *
 * Dockerfile, Kubernetes YAML, Terraform 등 IaC 파일의 보안 취약점을 검사합니다.
 */
server.registerTool(
    'scan-iac',
    {
        title: 'Infrastructure as Code 보안 스캔',
        description: 'Dockerfile, Kubernetes YAML, Terraform 등 IaC 파일의 보안 취약점 검사',
        inputSchema: {
            filePath: z.string().describe('스캔할 IaC 파일 경로'),
            iacType: z.enum(['dockerfile', 'kubernetes', 'terraform', 'auto'])
                .default('auto')
                .describe('IaC 파일 타입 (auto면 자동 감지)'),
        },
    },
    async ({ filePath, iacType }) => {
        const detectedType: IaCType = iacType === 'auto'
            ? detectIaCType(filePath)
            : iacType as IaCType;

        const issues = await scanIaCFile(filePath, detectedType);
        const result = formatIaCScanResult(issues, detectedType);

        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * 종합 보안 리포트 생성
 *
 * 스캔 결과를 기반으로 Mermaid 다이어그램, SARIF, CVE 정보 등을 포함한
 * 고급 보안 리포트를 생성합니다.
 */
server.registerTool(
    'generate-security-report',
    {
        title: '종합 보안 리포트 생성',
        description: '스캔 결과를 기반으로 Mermaid 다이어그램, SARIF, CVE/OWASP 정보 포함한 종합 리포트 생성',
        inputSchema: {
            code: z.string().optional().describe('검사할 코드 (선택사항)'),
            filePath: z.string().optional().describe('검사할 파일 경로 (선택사항)'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto')
                .describe('프로그래밍 언어'),
            format: z.enum(['markdown', 'sarif', 'both'])
                .default('both')
                .describe('리포트 포맷'),
            enrichWithCVE: z.boolean()
                .default(false)
                .describe('CVE/NVD 정보로 enrichment 할지 여부 (느릴 수 있음)'),
        },
    },
    async ({ code, filePath, language, format, enrichWithCVE }) => {
        const issues: SecurityIssue[] = [];

        // 코드 스캔 또는 파일 스캔
        if (code) {
            const detectedLang = language === 'auto' ? detectLanguage(code) : language;
            issues.push(...scanSecrets(code));
            issues.push(...scanInjection(code, detectedLang));
            issues.push(...scanXss(code, detectedLang));
            issues.push(...scanCrypto(code, detectedLang));
            issues.push(...scanAuth(code, detectedLang));
            issues.push(...scanPath(code, detectedLang));
        } else if (filePath) {
            // IaC 파일인지 확인
            const iacType = detectIaCType(filePath);
            if (iacType !== 'unknown') {
                issues.push(...await scanIaCFile(filePath, iacType));
            } else {
                return {
                    content: [{
                        type: 'text',
                        text: '⚠️ code 또는 filePath 중 하나는 필수입니다. IaC 파일인 경우 filePath를 사용하세요.'
                    }]
                };
            }
        } else {
            return {
                content: [{
                    type: 'text',
                    text: '⚠️ code 또는 filePath 중 하나는 필수입니다.'
                }]
            };
        }

        // CVE Enrichment (선택사항)
        if (enrichWithCVE) {
            await enrichIssuesWithCVE(issues);
        }

        // OWASP 정보 enrichment
        enrichIssuesWithOWASP(issues);

        let result = '';

        // Markdown 리포트 생성
        if (format === 'markdown' || format === 'both') {
            result += generateSecurityDashboard(issues);
            result += '\n\n---\n\n';
            result += generateDetailedIssueList(issues);
        }

        // SARIF 리포트 생성
        if (format === 'sarif' || format === 'both') {
            if (format === 'both') {
                result += '\n\n## 📄 SARIF Report\n\n';
                result += '```json\n';
            }

            const sarifReport = generateSARIFReport(issues, filePath || 'scan-result.js');
            result += sarifToJSON(sarifReport, true);

            if (format === 'both') {
                result += '\n```';
            }
        }

        return { content: [{ type: 'text', text: result }] };
    }
);

/**
 * 샌드박스 환경에서 보안 스캔 실행
 *
 * Docker 컨테이너를 사용하여 격리된 환경에서 스캔을 실행합니다.
 * 악의적인 코드로부터 호스트 시스템을 보호합니다.
 */
server.registerTool(
    'scan-in-sandbox',
    {
        title: '샌드박스 환경에서 보안 스캔',
        description: 'Docker 컨테이너를 사용하여 격리된 환경에서 안전하게 보안 스캔 실행',
        inputSchema: {
            code: z.string().describe('검사할 코드'),
            language: z.enum(['javascript', 'typescript', 'python', 'java', 'go', 'auto'])
                .default('auto')
                .describe('프로그래밍 언어'),
            timeout: z.number()
                .min(5000)
                .max(300000)
                .default(30000)
                .describe('타임아웃 (ms, 5초 ~ 5분)'),
            memoryLimit: z.number()
                .min(128)
                .max(2048)
                .default(512)
                .describe('메모리 제한 (MB)'),
            cpuLimit: z.number()
                .min(0.1)
                .max(2.0)
                .default(0.5)
                .describe('CPU 제한 (코어 수)'),
        },
    },
    async ({ code, language, timeout, memoryLimit, cpuLimit }) => {
        // Docker 사용 가능 여부 확인
        const dockerAvailable = await dockerSandboxManager.isDockerAvailable();
        if (!dockerAvailable) {
            return {
                content: [{
                    type: 'text',
                    text: '⚠️ Docker가 설치되어 있지 않거나 실행 중이 아닙니다. 일반 스캔을 대신 사용하세요.'
                }]
            };
        }

        // 이미지 존재 여부 확인
        const imageName = 'security-scanner-mcp:latest';
        const imageExists = await dockerSandboxManager.imageExists(imageName);

        if (!imageExists) {
            return {
                content: [{
                    type: 'text',
                    text: `⚠️ Docker 이미지 '${imageName}'가 존재하지 않습니다.\n\n다음 명령어로 이미지를 빌드하세요:\n\`\`\`bash\nnpm run docker:build\n\`\`\``
                }]
            };
        }

        try {
            // 임시 파일 생성
            const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scanner-'));
            const tmpFile = path.join(tmpDir, 'code-to-scan.txt');

            await fs.writeFile(tmpFile, code, 'utf-8');

            // Docker에서 스캔 실행 (scanner-entrypoint.js 실행)
            const result = await dockerSandboxManager.run({
                image: imageName,
                command: [], // 기본 CMD 사용 (scanner-entrypoint.js)
                env: {
                    NODE_ENV: 'production',
                    SCAN_LANGUAGE: language,
                    SCAN_CODE_FILE: '/tmp/code.txt',
                },
                cpuLimit,
                memoryLimit,
                timeout,
                noNetwork: true,
                readonlyRootfs: false,
                volumes: [
                    {
                        host: tmpFile,
                        container: '/tmp/code.txt',
                        readonly: true,
                    }
                ],
            });

            // 임시 파일 정리
            await fs.rm(tmpDir, { recursive: true, force: true });

            // 결과 포맷팅
            let response = '## 🐳 샌드박스 스캔 결과\n\n';

            if (result.timedOut) {
                response += `⏱️ **타임아웃 발생** (${timeout}ms)\n\n`;
                response += '스캔이 제한 시간 내에 완료되지 않았습니다.\n';
            } else if (!result.success) {
                response += `❌ **스캔 실패** (Exit Code: ${result.exitCode})\n\n`;
                if (result.stderr) {
                    response += `**에러**:\n\`\`\`\n${result.stderr}\n\`\`\`\n`;
                }
            } else {
                // JSON 결과 파싱
                try {
                    const scanResult = JSON.parse(result.stdout);

                    if (scanResult.success) {
                        response += `✅ **스캔 완료**\n\n`;
                        response += `- **언어**: ${scanResult.language}\n`;
                        response += `- **발견된 취약점**: ${scanResult.issuesCount}개\n\n`;

                        if (scanResult.issuesCount > 0) {
                            // 심각도별 요약
                            response += `### 📊 심각도별 통계\n\n`;
                            response += `| 심각도 | 개수 |\n`;
                            response += `|--------|------|\n`;
                            if (scanResult.summary.critical > 0) {
                                response += `| 🔴 Critical | ${scanResult.summary.critical} |\n`;
                            }
                            if (scanResult.summary.high > 0) {
                                response += `| 🟠 High | ${scanResult.summary.high} |\n`;
                            }
                            if (scanResult.summary.medium > 0) {
                                response += `| 🟡 Medium | ${scanResult.summary.medium} |\n`;
                            }
                            if (scanResult.summary.low > 0) {
                                response += `| 🟢 Low | ${scanResult.summary.low} |\n`;
                            }
                            response += '\n';

                            // 취약점 상세 목록
                            response += `### 🔍 발견된 취약점\n\n`;

                            const critical = scanResult.issues.filter((i: any) => i.severity === 'critical');
                            const high = scanResult.issues.filter((i: any) => i.severity === 'high');
                            const medium = scanResult.issues.filter((i: any) => i.severity === 'medium');
                            const low = scanResult.issues.filter((i: any) => i.severity === 'low');

                            if (critical.length > 0) {
                                response += `#### 🔴 Critical (${critical.length}개)\n\n`;
                                for (const issue of critical) {
                                    response += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
                                    response += `  - ${issue.message}\n`;
                                    response += `  - 💡 해결책: ${issue.fix}\n\n`;
                                }
                            }

                            if (high.length > 0) {
                                response += `#### 🟠 High (${high.length}개)\n\n`;
                                for (const issue of high) {
                                    response += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
                                    response += `  - ${issue.message}\n`;
                                    response += `  - 💡 해결책: ${issue.fix}\n\n`;
                                }
                            }

                            if (medium.length > 0) {
                                response += `#### 🟡 Medium (${medium.length}개)\n\n`;
                                for (const issue of medium) {
                                    response += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
                                    response += `  - ${issue.message}\n\n`;
                                }
                            }

                            if (low.length > 0) {
                                response += `#### 🟢 Low (${low.length}개)\n\n`;
                                for (const issue of low) {
                                    response += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
                                    response += `  - ${issue.message}\n\n`;
                                }
                            }
                        } else {
                            response += `✨ **축하합니다!** 발견된 보안 취약점이 없습니다.\n\n`;
                        }
                    } else {
                        response += `❌ **스캔 실패**\n\n`;
                        response += `에러: ${scanResult.error}\n\n`;
                    }
                } catch (parseError) {
                    response += `❌ **결과 파싱 실패**\n\n`;
                    response += `원본 출력:\n\`\`\`\n${result.stdout}\n\`\`\`\n`;
                }
            }

            response += `\n### 🔒 샌드박스 설정\n\n`;
            response += `- **메모리 제한**: ${memoryLimit}MB\n`;
            response += `- **CPU 제한**: ${cpuLimit} 코어\n`;
            response += `- **타임아웃**: ${timeout}ms\n`;
            response += `- **네트워크**: 비활성화\n`;
            response += `- **권한**: 최소 권한\n`;

            return { content: [{ type: 'text', text: response }] };

        } catch (error) {
            return {
                content: [{
                    type: 'text',
                    text: `❌ 샌드박스 실행 중 에러 발생:\n\n${error instanceof Error ? error.message : String(error)}`
                }]
            };
        }
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

/**
 * CVE 정보로 issue enrichment
 */
async function enrichIssuesWithCVE(issues: SecurityIssue[]): Promise<void> {
    for (const issue of issues) {
        // metadata에 cveIds가 있으면 조회
        if (issue.metadata?.cveIds && Array.isArray(issue.metadata.cveIds)) {
            const cveInfos = await cveLookupClient.lookupMultipleCVEs(issue.metadata.cveIds);
            issue.metadata.cveDetails = Array.from(cveInfos.values());
        }
    }
}

/**
 * OWASP 정보로 issue enrichment
 */
function enrichIssuesWithOWASP(issues: SecurityIssue[]): void {
    for (const issue of issues) {
        // OWASP 카테고리 정보
        if (issue.owaspCategory) {
            const owaspInfo = getOWASPInfo(issue.owaspCategory);
            if (owaspInfo) {
                issue.metadata = issue.metadata || {};
                issue.metadata.owaspInfo = owaspInfo;
            }
        }

        // CWE 정보
        if (issue.cweId) {
            const cweInfo = getCWEInfo(issue.cweId);
            if (cweInfo) {
                issue.metadata = issue.metadata || {};
                issue.metadata.cweInfo = cweInfo;
            }
        }
    }
}

/**
 * 상세 이슈 목록 생성
 */
function generateDetailedIssueList(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return '## ✅ 발견된 취약점 없음\n\n코드가 안전합니다!';
    }

    let result = '## 📋 발견된 취약점 상세 목록\n\n';

    const critical = issues.filter(i => i.severity === 'critical');
    const high = issues.filter(i => i.severity === 'high');
    const medium = issues.filter(i => i.severity === 'medium');
    const low = issues.filter(i => i.severity === 'low');

    const formatIssue = (issue: SecurityIssue, index: number) => {
        let output = `### ${index}. ${issue.type}\n\n`;
        output += `- **심각도**: ${getSeverityEmoji(issue.severity)} ${issue.severity.toUpperCase()}\n`;
        output += `- **메시지**: ${issue.message}\n`;

        if (issue.line) {
            output += `- **위치**: 라인 ${issue.line}\n`;
        }

        if (issue.match) {
            output += `- **코드**: \`${issue.match}\`\n`;
        }

        output += `- **해결책**: ${issue.fix}\n`;

        if (issue.owaspCategory) {
            output += `- **OWASP**: ${issue.owaspCategory}\n`;

            // OWASP 상세 정보
            if (issue.metadata?.owaspInfo) {
                output += `  - ${issue.metadata.owaspInfo.description}\n`;
            }
        }

        if (issue.cweId) {
            output += `- **CWE**: ${issue.cweId}\n`;

            // CWE 상세 정보
            if (issue.metadata?.cweInfo) {
                output += `  - ${issue.metadata.cweInfo.description}\n`;
            }
        }

        // CVE 정보
        if (issue.metadata?.cveDetails && Array.isArray(issue.metadata.cveDetails)) {
            output += `- **관련 CVE**:\n`;
            for (const cve of issue.metadata.cveDetails) {
                output += `  - **${cve.id}** (CVSS: ${cve.cvssV3Score || cve.cvssV2Score || 'N/A'})\n`;
                output += `    - ${cve.description}\n`;
            }
        }

        output += '\n';
        return output;
    };

    if (critical.length > 0) {
        result += `### 🔴 Critical (${critical.length}개)\n\n`;
        critical.forEach((issue, idx) => {
            result += formatIssue(issue, idx + 1);
        });
    }

    if (high.length > 0) {
        result += `### 🟠 High (${high.length}개)\n\n`;
        high.forEach((issue, idx) => {
            result += formatIssue(issue, idx + 1);
        });
    }

    if (medium.length > 0) {
        result += `### 🟡 Medium (${medium.length}개)\n\n`;
        medium.forEach((issue, idx) => {
            result += formatIssue(issue, idx + 1);
        });
    }

    if (low.length > 0) {
        result += `### 🟢 Low (${low.length}개)\n\n`;
        low.forEach((issue, idx) => {
            result += formatIssue(issue, idx + 1);
        });
    }

    return result;
}

function getSeverityEmoji(severity: Severity): string {
    const emojis = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🟢'
    };
    return emojis[severity];
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
