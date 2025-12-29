/**
 * Terraform 보안 스캐너
 *
 * Terraform (.tf) 파일의 보안 취약점을 검사합니다.
 * 간단한 패턴 매칭 기반 (완전한 HCL 파싱은 추후 개선)
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';
import * as fs from 'fs/promises';

interface TerraformRule {
    id: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
}

/**
 * Terraform 보안 규칙
 */
const TERRAFORM_RULES: TerraformRule[] = [
    // AWS 관련
    {
        id: 'TF001',
        pattern: /resource\s+"aws_security_group"[^}]*ingress\s*\{[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/s,
        severity: 'high',
        message: 'Security Group이 인터넷 전체(0.0.0.0/0)에 오픈되어 있습니다.',
        fix: '필요한 IP 범위로만 제한하세요',
    },
    {
        id: 'TF002',
        pattern: /resource\s+"aws_s3_bucket"[^}]*acl\s*=\s*"public-read"/s,
        severity: 'critical',
        message: 'S3 버킷이 public-read로 설정되어 있습니다.',
        fix: 'acl을 private으로 변경하고 필요시 bucket policy 사용',
    },
    {
        id: 'TF003',
        pattern: /resource\s+"aws_db_instance"[^}]*publicly_accessible\s*=\s*true/s,
        severity: 'critical',
        message: 'RDS 인스턴스가 public 접근이 가능합니다.',
        fix: 'publicly_accessible = false 설정',
    },
    {
        id: 'TF004',
        pattern: /resource\s+"aws_instance"[^}]*associate_public_ip_address\s*=\s*true/s,
        severity: 'medium',
        message: 'EC2 인스턴스에 Public IP가 자동 할당됩니다.',
        fix: 'Private subnet에 배치하고 NAT Gateway 사용',
    },
    {
        id: 'TF005',
        pattern: /resource\s+"aws_s3_bucket"(?![^}]*server_side_encryption_configuration)/s,
        severity: 'high',
        message: 'S3 버킷 암호화가 설정되지 않았습니다.',
        fix: 'server_side_encryption_configuration 블록 추가',
    },
    {
        id: 'TF006',
        pattern: /resource\s+"aws_db_instance"(?![^}]*storage_encrypted\s*=\s*true)/s,
        severity: 'high',
        message: 'RDS storage 암호화가 비활성화되어 있습니다.',
        fix: 'storage_encrypted = true 설정',
    },

    // 하드코딩된 시크릿
    {
        id: 'TF007',
        pattern: /(?:password|secret|token|api_key)\s*=\s*"[^"]{8,}"/i,
        severity: 'critical',
        message: '하드코딩된 시크릿이 발견되었습니다.',
        fix: 'AWS Secrets Manager나 환경변수 사용. 예: data.aws_secretsmanager_secret_version',
    },
    {
        id: 'TF008',
        pattern: /access_key\s*=\s*"AKIA[A-Z0-9]{16}"/,
        severity: 'critical',
        message: 'AWS Access Key가 하드코딩되어 있습니다.',
        fix: 'IAM Role 사용 또는 AWS CLI 프로파일 사용',
    },

    // 로깅 설정
    {
        id: 'TF009',
        pattern: /resource\s+"aws_s3_bucket"(?![^}]*logging\s*\{)/s,
        severity: 'medium',
        message: 'S3 버킷 로깅이 비활성화되어 있습니다.',
        fix: 'logging 블록 추가',
    },
    {
        id: 'TF010',
        pattern: /resource\s+"aws_cloudtrail"[^}]*enable_logging\s*=\s*false/s,
        severity: 'high',
        message: 'CloudTrail 로깅이 비활성화되어 있습니다.',
        fix: 'enable_logging = true 설정',
    },

    // GCP 관련
    {
        id: 'TF011',
        pattern: /resource\s+"google_compute_firewall"[^}]*source_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/s,
        severity: 'high',
        message: 'GCP Firewall이 인터넷 전체에 오픈되어 있습니다.',
        fix: '필요한 IP 범위로만 제한하세요',
    },
    {
        id: 'TF012',
        pattern: /resource\s+"google_storage_bucket"[^}]*uniform_bucket_level_access\s*=\s*false/s,
        severity: 'medium',
        message: 'GCS 버킷에서 uniform access가 비활성화되어 있습니다.',
        fix: 'uniform_bucket_level_access = true 설정',
    },

    // Azure 관련
    {
        id: 'TF013',
        pattern: /resource\s+"azurerm_network_security_rule"[^}]*source_address_prefix\s*=\s*"\*"/s,
        severity: 'high',
        message: 'Azure NSG가 모든 소스에서 접근 가능합니다.',
        fix: '특정 IP 범위로 제한',
    },

    // 일반 보안 설정
    {
        id: 'TF014',
        pattern: /enable_http\s*=\s*true|protocol\s*=\s*"HTTP"/i,
        severity: 'medium',
        message: 'HTTP (암호화되지 않음) 사용',
        fix: 'HTTPS 사용',
    },
    {
        id: 'TF015',
        pattern: /min_tls_version\s*=\s*"1\.[01]"|ssl_policy\s*=\s*".*TLSv1[^_2]"/i,
        severity: 'high',
        message: 'TLS 1.0/1.1은 더 이상 안전하지 않습니다.',
        fix: 'TLS 1.2 이상 사용',
    },
];

/**
 * Terraform 파일 스캔
 */
export async function scanTerraform(filePath: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    try {
        const content = await fs.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        for (const rule of TERRAFORM_RULES) {
            rule.pattern.lastIndex = 0;
            const matches = content.matchAll(new RegExp(rule.pattern, 'gs'));

            for (const match of matches) {
                const lineNumber = findLineNumber(content, match.index || 0);
                const line = lines[lineNumber - 1];

                // 주석 스킵
                if (line && (line.trim().startsWith('#') || line.trim().startsWith('//'))) {
                    continue;
                }

                issues.push({
                    type: `Terraform: ${rule.id}`,
                    severity: rule.severity,
                    message: rule.message,
                    fix: rule.fix,
                    line: lineNumber,
                    match: line?.trim().slice(0, 80),
                    owaspCategory: 'A05:2021 – Security Misconfiguration',
                    cweId: 'CWE-732',
                    metadata: {
                        ruleId: rule.id,
                    }
                });
            }
        }

        // 추가 보안 체크
        issues.push(...checkProviderVersions(content, lines));
        issues.push(...checkBackendConfiguration(content, lines));

    } catch (error) {
        console.error(`Terraform 스캔 실패 (${filePath}):`, error);
    }

    return issues;
}

/**
 * Provider 버전 고정 확인
 */
function checkProviderVersions(content: string, lines: string[]): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // terraform 블록에서 required_providers 찾기
    const providerRegex = /required_providers\s*\{([^}]+)\}/s;
    const match = content.match(providerRegex);

    if (!match) {
        issues.push({
            type: 'Terraform: Best Practice',
            severity: 'low',
            message: 'Provider 버전이 고정되지 않았습니다.',
            fix: 'terraform { required_providers { ... } } 블록에서 버전 지정',
            owaspCategory: 'A05:2021 – Security Misconfiguration',
        });
    }

    return issues;
}

/**
 * Backend 설정 확인
 */
function checkBackendConfiguration(content: string, lines: string[]): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // backend "s3" 블록에서 encryption 확인
    const s3BackendRegex = /backend\s+"s3"\s*\{([^}]+)\}/s;
    const match = content.match(s3BackendRegex);

    if (match && !match[1].includes('encrypt')) {
        const lineNumber = findLineNumber(content, match.index || 0);

        issues.push({
            type: 'Terraform: Backend Security',
            severity: 'high',
            message: 'S3 backend에 암호화가 설정되지 않았습니다.',
            fix: 's3 backend 블록에 encrypt = true 추가',
            line: lineNumber,
            owaspCategory: 'A02:2021 – Cryptographic Failures',
        });
    }

    return issues;
}

/**
 * 라인 번호 찾기
 */
function findLineNumber(content: string, index: number): number {
    const beforeMatch = content.slice(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
}

/**
 * Terraform 스캔 결과 포맷팅
 */
export function formatTerraformScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ Terraform 보안 검사 통과!

발견된 보안 취약점이 없습니다.`;
    }

    let result = `## 🏗️ Terraform 보안 취약점 발견!

총 **${issues.length}개**의 취약점이 발견되었습니다.

`;

    const critical = issues.filter(i => i.severity === 'critical');
    const high = issues.filter(i => i.severity === 'high');
    const medium = issues.filter(i => i.severity === 'medium');
    const low = issues.filter(i => i.severity === 'low');

    if (critical.length > 0) {
        result += `### 🔴 Critical (${critical.length}개)\n\n`;
        result += formatIssueList(critical);
    }

    if (high.length > 0) {
        result += `### 🟠 High (${high.length}개)\n\n`;
        result += formatIssueList(high);
    }

    if (medium.length > 0) {
        result += `### 🟡 Medium (${medium.length}개)\n\n`;
        result += formatIssueList(medium);
    }

    if (low.length > 0) {
        result += `### 🟢 Low (${low.length}개)\n\n`;
        result += formatIssueList(low);
    }

    result += `\n---\n\n**권장 도구**: \`tfsec\`, \`checkov\`, \`terrascan\`을 사용하여 더 상세한 분석을 수행하세요.`;

    return result;
}

function formatIssueList(issues: SecurityIssue[]): string {
    return issues.map(issue => `
- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}
  - ${issue.message}
  - 💡 해결책: ${issue.fix}
`).join('') + '\n';
}
