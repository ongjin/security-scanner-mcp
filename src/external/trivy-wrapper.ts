/**
 * Trivy Wrapper
 * Trivy 도구를 실행하고 결과를 파싱합니다.
 * 주로 IaC 파일(Dockerfile, Kubernetes, Terraform) 스캔에 사용
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
 * Trivy JSON 출력 형식
 */
interface TrivyResult {
    Results?: Array<{
        Target: string;
        Class: string;
        Type: string;
        Misconfigurations?: TrivyMisconfiguration[];
        Vulnerabilities?: TrivyVulnerability[];
    }>;
}

interface TrivyMisconfiguration {
    Type: string;
    ID: string;
    Title: string;
    Description: string;
    Message: string;
    Resolution: string;
    Severity: string;
    PrimaryURL: string;
    References: string[];
    Status: string;
    Layer: any;
    CauseMetadata: {
        Provider: string;
        Service: string;
        StartLine: number;
        EndLine: number;
        Code: {
            Lines: Array<{
                Number: number;
                Content: string;
                IsCause: boolean;
                Annotation: string;
                Truncated: boolean;
                Highlighted: string;
                FirstCause: boolean;
                LastCause: boolean;
            }>;
        };
    };
}

interface TrivyVulnerability {
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion: string;
    FixedVersion: string;
    Severity: string;
    Description: string;
    References: string[];
    PrimaryURL: string;
    Title: string;
}

/**
 * Trivy를 사용하여 IaC 파일 스캔
 */
export async function scanWithTrivy(
    code: string,
    filename: string,
    scanType: 'config' | 'vuln' = 'config'
): Promise<SecurityIssue[]> {
    // Trivy 설치 확인
    const hasTrivy = await checkTrivyInstalled();
    if (!hasTrivy) {
        console.warn('Trivy not installed, skipping...');
        return [];
    }

    // 파일 타입 결정
    const fileType = determineFileType(filename);
    if (!fileType) {
        return []; // 지원하지 않는 파일 타입
    }

    // 임시 파일 생성
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trivy-'));
    const tmpFile = path.join(tmpDir, filename);
    fs.writeFileSync(tmpFile, code);

    try {
        const scanners = scanType === 'config' ? 'config' : 'vuln';

        // Trivy 실행
        const { stdout } = await execAsync(
            `trivy fs --scanners ${scanners} --format json --quiet ${tmpFile}`,
            { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
        );

        if (!stdout.trim()) {
            return [];
        }

        const results: TrivyResult = JSON.parse(stdout);

        // SecurityIssue 포맷으로 변환
        const issues: SecurityIssue[] = [];

        if (results.Results) {
            for (const result of results.Results) {
                // Misconfiguration (IaC 이슈)
                if (result.Misconfigurations) {
                    for (const misc of result.Misconfigurations) {
                        issues.push(convertTrivyMisconfigToSecurityIssue(misc, fileType));
                    }
                }

                // Vulnerabilities (의존성 취약점)
                if (result.Vulnerabilities) {
                    for (const vuln of result.Vulnerabilities) {
                        issues.push(convertTrivyVulnToSecurityIssue(vuln));
                    }
                }
            }
        }

        return issues;
    } catch (error: any) {
        console.error('Trivy scan error:', error.message);
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
 * Trivy Misconfiguration을 SecurityIssue로 변환
 */
function convertTrivyMisconfigToSecurityIssue(
    misc: TrivyMisconfiguration,
    fileType: string
): SecurityIssue {
    const severity = mapTrivySeverity(misc.Severity);

    return {
        type: misc.ID || misc.Type,
        severity,
        message: misc.Message || misc.Title || misc.Description,
        fix: misc.Resolution || 'See Trivy documentation for remediation',
        line: misc.CauseMetadata?.StartLine,
        owaspCategory: getOwaspCategoryForIaC(fileType),
        cweId: getCweForMisconfiguration(misc.ID),
        metadata: {
            tool: 'trivy',
            scanType: 'config',
            id: misc.ID,
            references: misc.References,
            primaryUrl: misc.PrimaryURL,
            fileType
        }
    };
}

/**
 * Trivy Vulnerability를 SecurityIssue로 변환
 */
function convertTrivyVulnToSecurityIssue(vuln: TrivyVulnerability): SecurityIssue {
    const severity = mapTrivySeverity(vuln.Severity);

    return {
        type: `Vulnerable Dependency: ${vuln.PkgName}`,
        severity,
        message: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.Description}`,
        fix: vuln.FixedVersion
            ? `Update ${vuln.PkgName} from ${vuln.InstalledVersion} to ${vuln.FixedVersion}`
            : `Update ${vuln.PkgName} (no fixed version available yet)`,
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        cweId: 'CWE-1035',
        metadata: {
            tool: 'trivy',
            scanType: 'vuln',
            cve: vuln.VulnerabilityID,
            package: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            references: vuln.References,
            primaryUrl: vuln.PrimaryURL
        }
    };
}

/**
 * Trivy 심각도를 우리 심각도로 매핑
 */
function mapTrivySeverity(severity: string): Severity {
    const lower = severity.toLowerCase();
    if (lower === 'critical') return 'critical';
    if (lower === 'high') return 'high';
    if (lower === 'medium') return 'medium';
    return 'low';
}

/**
 * 파일 타입 결정
 */
function determineFileType(filename: string): string | null {
    const lower = filename.toLowerCase();

    if (lower === 'dockerfile' || lower.endsWith('.dockerfile')) {
        return 'dockerfile';
    }

    if (lower.endsWith('.yaml') || lower.endsWith('.yml')) {
        return 'kubernetes';
    }

    if (lower.endsWith('.tf') || lower.endsWith('.tfvars')) {
        return 'terraform';
    }

    return null;
}

/**
 * IaC 파일 타입에 따른 OWASP 카테고리
 */
function getOwaspCategoryForIaC(fileType: string): string {
    if (fileType === 'dockerfile') {
        return 'A05:2021 - Security Misconfiguration';
    }
    if (fileType === 'kubernetes') {
        return 'A05:2021 - Security Misconfiguration';
    }
    if (fileType === 'terraform') {
        return 'A05:2021 - Security Misconfiguration';
    }
    return 'A05:2021 - Security Misconfiguration';
}

/**
 * Misconfiguration ID로 CWE 매핑
 */
function getCweForMisconfiguration(id: string): string {
    const lower = id.toLowerCase();

    if (lower.includes('secret') || lower.includes('password')) {
        return 'CWE-798'; // Hard-coded Credentials
    }

    if (lower.includes('privilege') || lower.includes('root')) {
        return 'CWE-250'; // Execution with Unnecessary Privileges
    }

    if (lower.includes('network') || lower.includes('port')) {
        return 'CWE-923'; // Improper Restriction of Communication Channel
    }

    if (lower.includes('encryption') || lower.includes('crypto')) {
        return 'CWE-327'; // Use of a Broken or Risky Cryptographic Algorithm
    }

    return 'CWE-16'; // Configuration
}

/**
 * Trivy 설치 여부 확인
 */
async function checkTrivyInstalled(): Promise<boolean> {
    try {
        await execAsync('trivy --version', { timeout: 5000 });
        return true;
    } catch {
        return false;
    }
}
