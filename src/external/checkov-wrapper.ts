/**
 * Checkov Wrapper
 * Checkov 도구를 실행하고 결과를 파싱합니다.
 * IaC (Dockerfile, Kubernetes, Terraform) 보안 스캔
 *
 * @author zerry
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { SecurityIssue, Severity } from '../types.js';

const execAsync = promisify(exec);

/**
 * Checkov JSON 출력 형식
 */
interface CheckovResult {
    results?: {
        passed_checks?: CheckovCheck[];
        failed_checks?: CheckovCheck[];
        skipped_checks?: CheckovCheck[];
        parsing_errors?: string[];
    };
    summary?: {
        passed: number;
        failed: number;
        skipped: number;
        parsing_errors: number;
        resource_count: number;
    };
}

interface CheckovCheck {
    check_id: string;
    bc_check_id?: string;
    check_name: string;
    check_result: {
        result: string;
        evaluated_keys?: string[];
    };
    code_block?: Array<[number, string]>;
    file_path: string;
    file_line_range: [number, number];
    resource: string;
    evaluations?: any;
    check_class: string;
    guideline: string;
    severity?: string;
}

/**
 * Checkov를 사용하여 IaC 파일 스캔
 */
export async function scanWithCheckov(
    code: string,
    filename: string
): Promise<SecurityIssue[]> {
    // Checkov 설치 확인
    const hasCheckov = await checkCheckovInstalled();
    if (!hasCheckov) {
        console.warn('Checkov not installed, skipping...');
        return [];
    }

    // 파일 타입 결정
    const framework = determineFramework(filename);
    if (!framework) {
        return []; // 지원하지 않는 파일 타입
    }

    // 임시 파일 생성
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'checkov-'));
    const tmpFile = path.join(tmpDir, filename);
    fs.writeFileSync(tmpFile, code);

    try {
        // Checkov 실행
        const { stdout } = await execAsync(
            `checkov --framework ${framework} --output json --file ${tmpFile}`,
            { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
        );

        if (!stdout.trim()) {
            return [];
        }

        const results: CheckovResult = JSON.parse(stdout);

        // SecurityIssue 포맷으로 변환
        const issues: SecurityIssue[] = [];

        if (results.results?.failed_checks) {
            for (const check of results.results.failed_checks) {
                issues.push(convertCheckovToSecurityIssue(check, framework));
            }
        }

        return issues;
    } catch (error: any) {
        // Checkov는 실패한 체크가 있으면 exit code 1을 반환
        if (error.code === 1 && error.stdout) {
            try {
                const results: CheckovResult = JSON.parse(error.stdout);
                const issues: SecurityIssue[] = [];

                if (results.results?.failed_checks) {
                    for (const check of results.results.failed_checks) {
                        issues.push(convertCheckovToSecurityIssue(check, framework));
                    }
                }

                return issues;
            } catch {
                // JSON 파싱 실패
            }
        }

        console.error('Checkov scan error:', error.message);
        return [];
    } finally {
        // 임시 파일 정리
        try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {
            // 정리 실패 무시
        }
    }
}

/**
 * Checkov 체크를 SecurityIssue로 변환
 */
function convertCheckovToSecurityIssue(check: CheckovCheck, framework: string): SecurityIssue {
    // Severity 결정 (Checkov는 severity를 항상 제공하지 않음)
    const severity = determineSeverity(check);

    // 라인 번호
    const line = check.file_line_range ? check.file_line_range[0] : undefined;

    // 코드 블록 추출
    const codeSnippet = check.code_block
        ? check.code_block.map(([lineNum, content]) => content).join('\n')
        : undefined;

    return {
        type: check.check_name || check.check_id,
        severity,
        message: `${check.check_id}: ${check.check_name}`,
        fix: check.guideline || 'See Checkov documentation for remediation',
        line,
        match: codeSnippet,
        owaspCategory: getOwaspCategoryForFramework(framework),
        cweId: getCweForCheckId(check.check_id),
        metadata: {
            tool: 'checkov',
            checkId: check.check_id,
            bcCheckId: check.bc_check_id,
            resource: check.resource,
            framework,
            guideline: check.guideline
        }
    };
}

/**
 * Severity 결정
 */
function determineSeverity(check: CheckovCheck): Severity {
    // Checkov severity가 있으면 사용
    if (check.severity) {
        const lower = check.severity.toLowerCase();
        if (lower === 'critical') return 'critical';
        if (lower === 'high') return 'high';
        if (lower === 'medium') return 'medium';
        if (lower === 'low') return 'low';
    }

    // Check ID로 추론
    const checkId = check.check_id.toLowerCase();

    // Critical: 민감 정보, root 실행
    if (checkId.includes('secret') ||
        checkId.includes('password') ||
        checkId.includes('root') ||
        checkId.includes('privilege')) {
        return 'critical';
    }

    // High: 네트워크 노출, 암호화
    if (checkId.includes('public') ||
        checkId.includes('encryption') ||
        checkId.includes('network') ||
        checkId.includes('security-group')) {
        return 'high';
    }

    // Medium: 기본값
    return 'medium';
}

/**
 * 파일명으로 Checkov framework 결정
 */
function determineFramework(filename: string): string | null {
    const lower = filename.toLowerCase();

    if (lower === 'dockerfile' || lower.endsWith('.dockerfile')) {
        return 'dockerfile';
    }

    if (lower.endsWith('.yaml') || lower.endsWith('.yml')) {
        // Kubernetes YAML 판단 (내용 확인 필요할 수도 있음)
        return 'kubernetes';
    }

    if (lower.endsWith('.tf') || lower.endsWith('.tfvars')) {
        return 'terraform';
    }

    return null;
}

/**
 * Framework에 따른 OWASP 카테고리
 */
function getOwaspCategoryForFramework(framework: string): string {
    return 'A05:2021 - Security Misconfiguration';
}

/**
 * Check ID로 CWE 매핑
 */
function getCweForCheckId(checkId: string): string {
    const lower = checkId.toLowerCase();

    // CKV_DOCKER_1 등의 형식에서 유형 추론
    if (lower.includes('secret') || lower.includes('password') || lower.includes('key')) {
        return 'CWE-798'; // Hard-coded Credentials
    }

    if (lower.includes('root') || lower.includes('privilege')) {
        return 'CWE-250'; // Execution with Unnecessary Privileges
    }

    if (lower.includes('public') || lower.includes('network')) {
        return 'CWE-923'; // Improper Restriction of Communication Channel
    }

    if (lower.includes('encryption') || lower.includes('crypto')) {
        return 'CWE-327'; // Use of a Broken or Risky Cryptographic Algorithm
    }

    if (lower.includes('logging') || lower.includes('audit')) {
        return 'CWE-778'; // Insufficient Logging
    }

    return 'CWE-16'; // Configuration
}

/**
 * Checkov 설치 여부 확인
 */
async function checkCheckovInstalled(): Promise<boolean> {
    try {
        await execAsync('checkov --version', { timeout: 5000 });
        return true;
    } catch {
        return false;
    }
}
