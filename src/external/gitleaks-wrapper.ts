/**
 * GitLeaks Wrapper
 * GitLeaks 도구를 실행하고 결과를 파싱합니다.
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
 * GitLeaks JSON 출력 형식
 */
interface GitLeaksResult {
    Description: string;
    StartLine: number;
    EndLine: number;
    StartColumn: number;
    EndColumn: number;
    Match: string;
    Secret: string;
    File: string;
    SymlinkFile: string;
    Commit: string;
    Entropy: number;
    Author: string;
    Email: string;
    Date: string;
    Message: string;
    Tags: string[];
    RuleID: string;
    Fingerprint: string;
}

/**
 * GitLeaks를 사용하여 시크릿 스캔
 */
export async function scanWithGitLeaks(code: string, filename: string = 'scan.txt'): Promise<SecurityIssue[]> {
    // GitLeaks 설치 확인
    const hasGitLeaks = await checkGitLeaksInstalled();
    if (!hasGitLeaks) {
        console.warn('GitLeaks not installed, skipping...');
        return [];
    }

    // 임시 파일 생성
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitleaks-'));
    const tmpFile = path.join(tmpDir, filename);
    fs.writeFileSync(tmpFile, code);

    try {
        // GitLeaks 실행
        const { stdout } = await execAsync(
            `gitleaks detect --no-git --report-format json --report-path ${tmpDir}/report.json ${tmpFile}`,
            { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }
        );

        // 결과 파일 읽기
        const reportPath = path.join(tmpDir, 'report.json');
        if (!fs.existsSync(reportPath)) {
            return [];
        }

        const reportContent = fs.readFileSync(reportPath, 'utf-8');
        if (!reportContent.trim()) {
            return [];
        }

        const results: GitLeaksResult[] = JSON.parse(reportContent);

        // SecurityIssue 포맷으로 변환
        return results.map(result => convertGitLeaksToSecurityIssue(result));
    } catch (error: any) {
        // GitLeaks는 시크릿을 발견하면 exit code 1을 반환
        if (error.code === 1 && error.stdout) {
            try {
                const reportPath = path.join(tmpDir, 'report.json');
                if (fs.existsSync(reportPath)) {
                    const reportContent = fs.readFileSync(reportPath, 'utf-8');
                    const results: GitLeaksResult[] = JSON.parse(reportContent);
                    return results.map(result => convertGitLeaksToSecurityIssue(result));
                }
            } catch {
                // 파싱 실패
            }
        }

        console.error('GitLeaks scan error:', error.message);
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
 * GitLeaks 결과를 SecurityIssue로 변환
 */
function convertGitLeaksToSecurityIssue(result: GitLeaksResult): SecurityIssue {
    // RuleID로 심각도 결정
    const severity = determineSeverityFromRuleId(result.RuleID);

    // 시크릿 마스킹
    const maskedSecret = maskSecret(result.Secret);

    return {
        type: result.RuleID || 'Hardcoded Secret',
        severity,
        message: `${result.Description || 'Secret detected'}: ${maskedSecret}`,
        fix: getFixSuggestion(result.RuleID),
        line: result.StartLine,
        match: maskedSecret,
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        cweId: 'CWE-798',
        metadata: {
            tool: 'gitleaks',
            ruleId: result.RuleID,
            entropy: result.Entropy,
            tags: result.Tags
        }
    };
}

/**
 * Rule ID로 심각도 결정
 */
function determineSeverityFromRuleId(ruleId: string): Severity {
    const lowerRuleId = ruleId.toLowerCase();

    // Critical: 프로덕션 시크릿
    if (lowerRuleId.includes('aws') ||
        lowerRuleId.includes('private-key') ||
        lowerRuleId.includes('stripe') ||
        lowerRuleId.includes('google-api-key')) {
        return 'critical';
    }

    // High: 중요 API 키
    if (lowerRuleId.includes('api-key') ||
        lowerRuleId.includes('token') ||
        lowerRuleId.includes('secret')) {
        return 'high';
    }

    // Medium: 기타
    return 'medium';
}

/**
 * 시크릿 마스킹
 */
function maskSecret(secret: string): string {
    if (!secret || secret.length <= 8) {
        return '***';
    }

    const start = secret.substring(0, 4);
    const end = secret.substring(secret.length - 4);
    return `${start}...${end}`;
}

/**
 * Rule ID에 따른 해결책 제안
 */
function getFixSuggestion(ruleId: string): string {
    const lowerRuleId = ruleId.toLowerCase();

    if (lowerRuleId.includes('aws')) {
        return 'Use AWS Secrets Manager or environment variables with IAM roles';
    }

    if (lowerRuleId.includes('private-key')) {
        return 'Store private keys in secure vaults (HashiCorp Vault, AWS KMS) and use key rotation';
    }

    if (lowerRuleId.includes('google')) {
        return 'Use Google Cloud Secret Manager and restrict API key with IP/domain restrictions';
    }

    if (lowerRuleId.includes('github')) {
        return 'Use GitHub Secrets for Actions or environment variables';
    }

    return 'Store secrets in environment variables or use a secrets management service (Vault, AWS Secrets Manager, etc.)';
}

/**
 * GitLeaks 설치 여부 확인
 */
async function checkGitLeaksInstalled(): Promise<boolean> {
    try {
        await execAsync('gitleaks version', { timeout: 5000 });
        return true;
    } catch {
        return false;
    }
}
