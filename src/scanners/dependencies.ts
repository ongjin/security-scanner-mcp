/**
 * 의존성 취약점 스캐너
 *
 * package.json, requirements.txt 등을 분석해서
 * 알려진 취약점이 있는 패키지를 찾습니다.
 *
 * npm audit 같은 역할인데, MCP로 Claude가 직접 호출할 수 있어요.
 * 실제 프로덕션에서는 외부 취약점 DB (NVD, OSV 등)를 연동하면 더 좋습니다.
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * 알려진 취약한 패키지 목록
 *
 * 실제로는 외부 API (npm audit, Snyk, OSV 등)를 사용하는 게 좋지만,
 * 여기서는 자주 발견되는 취약 패키지들을 하드코딩해뒀어요.
 * 데모용이라고 생각해주세요!
 */
const KNOWN_VULNERABILITIES: Record<string, {
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
    affectedVersions?: string;
}> = {
    // 실제로 취약점이 있었던 유명 패키지들
    'lodash': {
        severity: 'high',
        message: '구버전에 Prototype Pollution 취약점이 있습니다.',
        fix: '최신 버전 (4.17.21 이상)으로 업데이트하세요.',
        affectedVersions: '<4.17.21',
    },
    'axios': {
        severity: 'medium',
        message: '구버전에 SSRF 취약점이 있습니다.',
        fix: '1.6.0 이상으로 업데이트하세요.',
        affectedVersions: '<1.6.0',
    },
    'express': {
        severity: 'medium',
        message: '구버전에 여러 보안 이슈가 있습니다.',
        fix: '4.18.0 이상으로 업데이트하세요.',
        affectedVersions: '<4.18.0',
    },
    'jsonwebtoken': {
        severity: 'high',
        message: '구버전에 알고리즘 confusion 취약점이 있습니다.',
        fix: '9.0.0 이상으로 업데이트하세요.',
        affectedVersions: '<9.0.0',
    },
    'minimist': {
        severity: 'high',
        message: 'Prototype Pollution 취약점이 있습니다.',
        fix: '1.2.6 이상으로 업데이트하세요.',
        affectedVersions: '<1.2.6',
    },
    'node-fetch': {
        severity: 'medium',
        message: '구버전에 URL bypass 취약점이 있습니다.',
        fix: '2.6.7 또는 3.x 이상으로 업데이트하세요.',
        affectedVersions: '<2.6.7',
    },
    'qs': {
        severity: 'high',
        message: 'Prototype Pollution 취약점이 있습니다.',
        fix: '6.10.3 이상으로 업데이트하세요.',
        affectedVersions: '<6.10.3',
    },
    'serialize-javascript': {
        severity: 'high',
        message: 'RCE 취약점이 있습니다.',
        fix: '3.1.0 이상으로 업데이트하세요.',
        affectedVersions: '<3.1.0',
    },
    'ua-parser-js': {
        severity: 'critical',
        message: '악성 코드가 삽입된 버전이 배포된 적 있습니다.',
        fix: '0.7.33, 0.8.1, 1.0.33 이상으로 업데이트하세요.',
    },
    'event-stream': {
        severity: 'critical',
        message: '악성 코드가 삽입된 버전(3.3.6)이 있습니다.',
        fix: '이 패키지 사용을 피하거나 안전한 버전만 사용하세요.',
    },
};

/**
 * 프로젝트의 의존성 취약점을 검사합니다.
 */
export async function scanDependencies(projectPath: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    // 1. package.json 검사 (Node.js)
    try {
        const packageJsonPath = path.join(projectPath, 'package.json');
        const content = await fs.readFile(packageJsonPath, 'utf-8');
        const packageJson = JSON.parse(content);

        const allDeps = {
            ...packageJson.dependencies,
            ...packageJson.devDependencies,
        };

        for (const [name, version] of Object.entries(allDeps)) {
            if (KNOWN_VULNERABILITIES[name]) {
                const vuln = KNOWN_VULNERABILITIES[name];

                // 버전 체크 (간단한 버전만 지원)
                if (vuln.affectedVersions && !isVersionAffected(version as string, vuln.affectedVersions)) {
                    continue;
                }

                issues.push({
                    type: `Vulnerable Package: ${name}`,
                    severity: vuln.severity,
                    message: vuln.message,
                    fix: vuln.fix,
                    match: `${name}@${version}`,
                    owaspCategory: 'A06:2021 – Vulnerable and Outdated Components',
                    cweId: 'CWE-1104',
                });
            }
        }

        // npm audit 실행 시도 (있으면)
        try {
            const auditIssues = await runNpmAudit(projectPath);
            issues.push(...auditIssues);
        } catch {
            // npm audit 실패해도 계속 진행
        }

    } catch {
        // package.json 없으면 스킵
    }

    // 2. requirements.txt 검사 (Python)
    try {
        const requirementsPath = path.join(projectPath, 'requirements.txt');
        const content = await fs.readFile(requirementsPath, 'utf-8');
        const pythonIssues = scanPythonDependencies(content);
        issues.push(...pythonIssues);
    } catch {
        // requirements.txt 없으면 스킵
    }

    // 3. go.mod 검사 (Go)
    try {
        const goModPath = path.join(projectPath, 'go.mod');
        const content = await fs.readFile(goModPath, 'utf-8');
        const goIssues = scanGoDependencies(content);
        issues.push(...goIssues);
    } catch {
        // go.mod 없으면 스킵
    }

    return issues;
}

/**
 * npm audit 실행
 */
async function runNpmAudit(projectPath: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    try {
        const { stdout } = await execAsync('npm audit --json', {
            cwd: projectPath,
            timeout: 30000,
        });

        const auditResult = JSON.parse(stdout);

        if (auditResult.vulnerabilities) {
            for (const [name, vuln] of Object.entries(auditResult.vulnerabilities) as any) {
                issues.push({
                    type: `npm audit: ${name}`,
                    severity: mapNpmSeverity(vuln.severity),
                    message: vuln.via?.[0]?.title || '취약점이 발견되었습니다.',
                    fix: vuln.fixAvailable
                        ? `npm audit fix 또는 ${name}을 ${vuln.fixAvailable.version || '최신'}으로 업데이트`
                        : '수동으로 업데이트가 필요합니다.',
                    match: `${name}@${vuln.range}`,
                });
            }
        }
    } catch {
        // npm audit 실패 (네트워크 없음 등)
    }

    return issues;
}

/**
 * Python 의존성 검사 (기본적인 패턴만)
 */
function scanPythonDependencies(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    const knownPythonVulns: Record<string, { severity: 'critical' | 'high' | 'medium' | 'low'; message: string; fix: string }> = {
        'pyyaml': {
            severity: 'critical',
            message: 'yaml.load()의 임의 코드 실행 취약점',
            fix: '5.4 이상 사용하고, yaml.safe_load() 사용',
        },
        'django': {
            severity: 'high',
            message: '구버전에 여러 보안 취약점이 있습니다.',
            fix: '최신 LTS 버전으로 업데이트하세요.',
        },
        'flask': {
            severity: 'medium',
            message: '구버전에 보안 이슈가 있을 수 있습니다.',
            fix: '최신 버전으로 업데이트하세요.',
        },
        'requests': {
            severity: 'medium',
            message: '구버전에 보안 이슈가 있습니다.',
            fix: '2.31.0 이상으로 업데이트하세요.',
        },
        'urllib3': {
            severity: 'medium',
            message: '구버전에 CRLF injection 취약점이 있습니다.',
            fix: '2.0.0 이상으로 업데이트하세요.',
        },
    };

    const lines = content.split('\n');
    for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)/);
        if (match) {
            const packageName = match[1].toLowerCase();
            if (knownPythonVulns[packageName]) {
                const vuln = knownPythonVulns[packageName];
                issues.push({
                    type: `Vulnerable Python Package: ${packageName}`,
                    severity: vuln.severity,
                    message: vuln.message,
                    fix: vuln.fix,
                    match: line.trim(),
                });
            }
        }
    }

    return issues;
}

/**
 * Go 의존성 검사 (기본적인 패턴만)
 */
function scanGoDependencies(content: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Go 취약 패키지들 (예시)
    const knownGoVulns: Record<string, { severity: 'critical' | 'high' | 'medium' | 'low'; message: string; fix: string }> = {
        'github.com/dgrijalva/jwt-go': {
            severity: 'high',
            message: '이 패키지는 deprecated되었고 취약점이 있습니다.',
            fix: 'github.com/golang-jwt/jwt/v5 로 마이그레이션하세요.',
        },
    };

    for (const [pkg, vuln] of Object.entries(knownGoVulns)) {
        if (content.includes(pkg)) {
            issues.push({
                type: `Vulnerable Go Package: ${pkg}`,
                severity: vuln.severity,
                message: vuln.message,
                fix: vuln.fix,
                match: pkg,
            });
        }
    }

    return issues;
}

/**
 * npm severity를 우리 형식으로 변환
 */
function mapNpmSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    switch (severity) {
        case 'critical': return 'critical';
        case 'high': return 'high';
        case 'moderate': return 'medium';
        default: return 'low';
    }
}

/**
 * 버전이 취약한 범위에 해당하는지 체크 (간단한 버전)
 *
 * 완벽하지 않아요. semver 라이브러리를 쓰면 더 정확합니다.
 */
function isVersionAffected(version: string, affected: string): boolean {
    // ^, ~, >= 등 제거하고 숫자만 추출
    const cleanVersion = version.replace(/[\^~>=<]/g, '');

    // affected가 <X.Y.Z 형태면 비교
    if (affected.startsWith('<')) {
        const affectedVersion = affected.slice(1);
        return compareVersions(cleanVersion, affectedVersion) < 0;
    }

    // 그 외의 경우 일단 취약하다고 가정 (보수적으로)
    return true;
}

/**
 * 간단한 버전 비교
 * v1 < v2 면 음수, 같으면 0, v1 > v2 면 양수
 */
function compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);

    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
        const p1 = parts1[i] || 0;
        const p2 = parts2[i] || 0;
        if (p1 !== p2) return p1 - p2;
    }

    return 0;
}
