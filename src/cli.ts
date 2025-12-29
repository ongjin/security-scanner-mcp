#!/usr/bin/env node
/**
 * Security Scanner CLI
 *
 * CI/CD 파이프라인, Jenkins, GitHub Actions 등에서 사용할 수 있는
 * 독립 실행형 보안 스캐너 CLI입니다.
 *
 * @example
 * # 파일 스캔
 * security-scanner-mcp scan ./src/app.js
 *
 * # 디렉토리 스캔
 * security-scanner-mcp scan ./src --format sarif --output report.sarif
 *
 * # MCP 서버 모드
 * security-scanner-mcp serve
 */

import { Command } from 'commander';
import * as fs from 'fs/promises';
import * as path from 'path';
import { scanSecrets } from './scanners/secrets.js';
import { scanInjection } from './scanners/injection.js';
import { scanXss } from './scanners/xss.js';
import { scanCrypto } from './scanners/crypto.js';
import { scanAuth } from './scanners/auth.js';
import { scanPath } from './scanners/path.js';
import { scanIaCFile, detectIaCType } from './iac-scanners/index.js';
import { generateSARIFReport, sarifToJSON } from './reporting/sarif-generator.js';
import { SecurityIssue, Severity } from './types.js';

// package.json에서 버전 가져오기
const packageJson = JSON.parse(
    await fs.readFile(new URL('../package.json', import.meta.url), 'utf-8')
);

const program = new Command();

// ============================================
// CLI 설정
// ============================================
program
    .name('security-scanner-mcp')
    .description('AI가 생성한 코드의 보안 취약점을 자동으로 검출하는 보안 스캐너')
    .version(packageJson.version);

// ============================================
// scan 명령어
// ============================================
program
    .command('scan <target>')
    .description('파일 또는 디렉토리의 보안 취약점 스캔')
    .option('-f, --format <format>', '출력 포맷 (text, json, sarif)', 'text')
    .option('-o, --output <file>', '결과를 파일로 저장')
    .option('-l, --language <lang>', '프로그래밍 언어 (auto, javascript, typescript, python, java, go)', 'auto')
    .option('-s, --severity <level>', '최소 심각도 필터 (critical, high, medium, low)', 'low')
    .option('--no-color', '색상 출력 비활성화')
    .option('--fail-on <level>', '지정된 심각도 이상 발견 시 exit code 1 반환', 'critical')
    .option('--include <patterns>', '포함할 파일 패턴 (쉼표 구분)', '*.js,*.ts,*.py,*.java,*.go')
    .option('--exclude <patterns>', '제외할 파일/디렉토리 패턴 (쉼표 구분)', 'node_modules,dist,build,.git')
    .action(async (target: string, options: ScanOptions) => {
        await runScan(target, options);
    });

// ============================================
// serve 명령어 (MCP 서버 모드)
// ============================================
program
    .command('serve')
    .description('MCP 서버 모드로 실행 (Claude Desktop/Code와 함께 사용)')
    .action(async () => {
        // 동적으로 MCP 서버 모듈 로드
        await import('./index.js');
    });

// ============================================
// 타입 정의
// ============================================
interface ScanOptions {
    format: 'text' | 'json' | 'sarif';
    output?: string;
    language: string;
    severity: Severity;
    color: boolean;
    failOn: Severity;
    include: string;
    exclude: string;
}

interface ScanSummary {
    totalFiles: number;
    scannedFiles: number;
    totalIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

// ============================================
// 스캔 실행
// ============================================
async function runScan(target: string, options: ScanOptions): Promise<void> {
    const startTime = Date.now();
    const allIssues: SecurityIssue[] = [];
    const scannedFiles: string[] = [];

    console.error('🔒 Security Scanner MCP - CLI Mode\n');

    try {
        const targetPath = path.resolve(target);
        const stats = await fs.stat(targetPath);

        if (stats.isDirectory()) {
            // 디렉토리 스캔
            console.error(`📂 디렉토리 스캔: ${targetPath}\n`);
            await scanDirectory(targetPath, allIssues, scannedFiles, options);
        } else if (stats.isFile()) {
            // 단일 파일 스캔
            console.error(`📄 파일 스캔: ${targetPath}\n`);
            await scanFile(targetPath, allIssues, options);
            scannedFiles.push(targetPath);
        }
    } catch (error) {
        console.error(`❌ 오류: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(1);
    }

    // 심각도 필터링
    const filteredIssues = filterBySeverity(allIssues, options.severity);

    // 결과 출력
    const summary: ScanSummary = {
        totalFiles: scannedFiles.length,
        scannedFiles: scannedFiles.length,
        totalIssues: filteredIssues.length,
        critical: filteredIssues.filter(i => i.severity === 'critical').length,
        high: filteredIssues.filter(i => i.severity === 'high').length,
        medium: filteredIssues.filter(i => i.severity === 'medium').length,
        low: filteredIssues.filter(i => i.severity === 'low').length,
    };

    const output = formatOutput(filteredIssues, summary, options, scannedFiles);

    // 출력
    if (options.output) {
        await fs.writeFile(options.output, output, 'utf-8');
        console.error(`📁 결과 저장됨: ${options.output}`);
    } else {
        console.log(output);
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
    console.error(`\n⏱️  완료: ${elapsed}초`);

    // Exit code 결정
    const shouldFail = hasIssuesAtOrAbove(filteredIssues, options.failOn);
    if (shouldFail) {
        console.error(`\n❌ ${options.failOn} 이상 심각도 취약점 발견 - exit code 1`);
        process.exit(1);
    }
}

// ============================================
// 디렉토리 스캔
// ============================================
async function scanDirectory(
    dirPath: string,
    allIssues: SecurityIssue[],
    scannedFiles: string[],
    options: ScanOptions
): Promise<void> {
    const includePatterns = options.include.split(',').map(p => p.trim());
    const excludePatterns = options.exclude.split(',').map(p => p.trim());

    const files = await getFilesRecursively(dirPath, includePatterns, excludePatterns);

    for (const file of files) {
        await scanFile(file, allIssues, options);
        scannedFiles.push(file);
    }
}

// ============================================
// 파일 스캔
// ============================================
async function scanFile(
    filePath: string,
    allIssues: SecurityIssue[],
    options: ScanOptions
): Promise<void> {
    try {
        const content = await fs.readFile(filePath, 'utf-8');
        const ext = path.extname(filePath).toLowerCase();

        // IaC 파일인지 확인
        const iacType = detectIaCType(filePath);
        if (iacType !== 'unknown') {
            const issues = await scanIaCFile(filePath, iacType);
            issues.forEach(issue => {
                issue.file = filePath;
                allIssues.push(issue);
            });
            return;
        }

        // 일반 코드 파일 스캔
        const language = options.language === 'auto' ? detectLanguage(ext) : options.language;

        const issues: SecurityIssue[] = [];
        issues.push(...scanSecrets(content));
        issues.push(...scanInjection(content, language));
        issues.push(...scanXss(content, language));
        issues.push(...scanCrypto(content, language));
        issues.push(...scanAuth(content, language));
        issues.push(...scanPath(content, language));

        // 파일 경로 추가
        issues.forEach(issue => {
            issue.file = filePath;
            allIssues.push(issue);
        });
    } catch (error) {
        console.error(`⚠️  파일 읽기 실패: ${filePath}`);
    }
}

// ============================================
// 유틸리티 함수들
// ============================================
async function getFilesRecursively(
    dir: string,
    includePatterns: string[],
    excludePatterns: string[]
): Promise<string[]> {
    const files: string[] = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        // 제외 패턴 확인
        if (matchesAnyPattern(entry.name, excludePatterns)) {
            continue;
        }

        if (entry.isDirectory()) {
            const subFiles = await getFilesRecursively(fullPath, includePatterns, excludePatterns);
            files.push(...subFiles);
        } else if (entry.isFile()) {
            // 포함 패턴 확인
            if (matchesAnyPattern(entry.name, includePatterns)) {
                files.push(fullPath);
            }
        }
    }

    return files;
}

function matchesAnyPattern(filename: string, patterns: string[]): boolean {
    return patterns.some(pattern => {
        // 간단한 glob 매칭 (*.js, *.ts 등)
        if (pattern.startsWith('*')) {
            return filename.endsWith(pattern.slice(1));
        }
        return filename === pattern || filename.includes(pattern);
    });
}

function detectLanguage(ext: string): string {
    const extMap: Record<string, string> = {
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.py': 'python',
        '.java': 'java',
        '.go': 'go',
    };

    return extMap[ext] || 'javascript';
}

function filterBySeverity(issues: SecurityIssue[], minSeverity: Severity): SecurityIssue[] {
    const severityOrder: Record<Severity, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
    };

    const minLevel = severityOrder[minSeverity];
    return issues.filter(issue => severityOrder[issue.severity] >= minLevel);
}

function hasIssuesAtOrAbove(issues: SecurityIssue[], level: Severity): boolean {
    const severityOrder: Record<Severity, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
    };

    const targetLevel = severityOrder[level];
    return issues.some(issue => severityOrder[issue.severity] >= targetLevel);
}

// ============================================
// 출력 포맷팅
// ============================================
function formatOutput(
    issues: SecurityIssue[],
    summary: ScanSummary,
    options: ScanOptions,
    scannedFiles: string[]
): string {
    switch (options.format) {
        case 'json':
            return formatJSON(issues, summary);
        case 'sarif':
            return formatSARIF(issues, scannedFiles);
        case 'text':
        default:
            return formatText(issues, summary, options.color);
    }
}

function formatJSON(issues: SecurityIssue[], summary: ScanSummary): string {
    return JSON.stringify({
        summary,
        issues: issues.map(issue => ({
            file: issue.file,
            line: issue.line,
            severity: issue.severity,
            type: issue.type,
            message: issue.message,
            fix: issue.fix,
            owaspCategory: issue.owaspCategory,
            cweId: issue.cweId,
        })),
    }, null, 2);
}

function formatSARIF(issues: SecurityIssue[], scannedFiles: string[]): string {
    const sarif = generateSARIFReport(issues, scannedFiles[0] || 'scan');
    return sarifToJSON(sarif, true);
}

function formatText(issues: SecurityIssue[], summary: ScanSummary, useColor: boolean): string {
    const c = {
        reset: useColor ? '\x1b[0m' : '',
        red: useColor ? '\x1b[31m' : '',
        yellow: useColor ? '\x1b[33m' : '',
        green: useColor ? '\x1b[32m' : '',
        cyan: useColor ? '\x1b[36m' : '',
        bold: useColor ? '\x1b[1m' : '',
    };

    let output = '';

    // 요약
    output += `${c.bold}════════════════════════════════════════${c.reset}\n`;
    output += `${c.bold}       Security Scanner MCP Report      ${c.reset}\n`;
    output += `${c.bold}════════════════════════════════════════${c.reset}\n\n`;

    output += `📊 스캔 결과 요약\n`;
    output += `────────────────────────────────────────\n`;
    output += `   스캔된 파일: ${summary.scannedFiles}개\n`;
    output += `   발견된 취약점: ${summary.totalIssues}개\n\n`;

    if (summary.totalIssues > 0) {
        output += `   ${c.red}🔴 Critical: ${summary.critical}${c.reset}\n`;
        output += `   ${c.yellow}🟠 High: ${summary.high}${c.reset}\n`;
        output += `   ${c.yellow}🟡 Medium: ${summary.medium}${c.reset}\n`;
        output += `   ${c.green}🟢 Low: ${summary.low}${c.reset}\n`;
    }

    output += `\n`;

    if (issues.length === 0) {
        output += `${c.green}✅ 발견된 취약점이 없습니다!${c.reset}\n`;
        return output;
    }

    // 취약점 상세
    output += `\n📋 발견된 취약점\n`;
    output += `────────────────────────────────────────\n\n`;

    const grouped = groupByFile(issues);

    for (const [file, fileIssues] of Object.entries(grouped)) {
        output += `${c.cyan}📄 ${file}${c.reset}\n`;

        for (const issue of fileIssues) {
            const severityIcon = getSeverityIcon(issue.severity);
            const severityColor = getSeverityColor(issue.severity, c);

            output += `\n   ${severityColor}${severityIcon} ${issue.type}${c.reset}`;
            if (issue.line) {
                output += ` (라인 ${issue.line})`;
            }
            output += `\n`;
            output += `      ${issue.message}\n`;
            output += `      💡 ${issue.fix}\n`;
        }

        output += `\n`;
    }

    return output;
}

function groupByFile(issues: SecurityIssue[]): Record<string, SecurityIssue[]> {
    const grouped: Record<string, SecurityIssue[]> = {};

    for (const issue of issues) {
        const file = issue.file || 'unknown';
        if (!grouped[file]) {
            grouped[file] = [];
        }
        grouped[file].push(issue);
    }

    return grouped;
}

function getSeverityIcon(severity: Severity): string {
    const icons: Record<Severity, string> = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🟢',
    };
    return icons[severity];
}

function getSeverityColor(severity: Severity, c: Record<string, string>): string {
    const colors: Record<Severity, string> = {
        critical: c.red,
        high: c.yellow,
        medium: c.yellow,
        low: c.green,
    };
    return colors[severity];
}

// ============================================
// CLI 실행
// ============================================
program.parse();
