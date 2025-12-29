/**
 * SARIF (Static Analysis Results Interchange Format) 생성기
 *
 * SARIF 2.1.0 스펙을 따르는 보안 스캔 결과를 생성합니다.
 * GitHub Code Scanning, Azure DevOps, VS Code 등에서 사용 가능합니다.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * @author zerry
 */

import { SecurityIssue, Severity } from '../types.js';

/**
 * SARIF 2.1.0 루트 객체
 */
interface SARIFReport {
    version: '2.1.0';
    $schema: string;
    runs: SARIFRun[];
}

/**
 * SARIF Run
 */
interface SARIFRun {
    tool: {
        driver: {
            name: string;
            version: string;
            informationUri: string;
            rules: SARIFRule[];
        };
    };
    results: SARIFResult[];
}

/**
 * SARIF Rule
 */
interface SARIFRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    fullDescription?: {
        text: string;
    };
    help?: {
        text: string;
        markdown?: string;
    };
    properties?: {
        tags?: string[];
        precision?: 'very-high' | 'high' | 'medium' | 'low';
        'security-severity'?: string;
    };
}

/**
 * SARIF Result
 */
interface SARIFResult {
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: {
        text: string;
    };
    locations?: Array<{
        physicalLocation: {
            artifactLocation: {
                uri: string;
            };
            region?: {
                startLine: number;
                snippet?: {
                    text: string;
                };
            };
        };
    }>;
    fixes?: Array<{
        description: {
            text: string;
        };
    }>;
}

/**
 * SARIF 리포트 생성
 */
export function generateSARIFReport(
    issues: SecurityIssue[],
    filePath?: string,
    toolVersion: string = '1.0.0'
): SARIFReport {
    // 규칙 추출 및 중복 제거
    const rulesMap = new Map<string, SARIFRule>();

    for (const issue of issues) {
        const ruleId = generateRuleId(issue);

        if (!rulesMap.has(ruleId)) {
            rulesMap.set(ruleId, createRule(issue));
        }
    }

    // 결과 생성
    const results: SARIFResult[] = issues.map(issue => createResult(issue, filePath));

    const report: SARIFReport = {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'Security Scanner MCP',
                        version: toolVersion,
                        informationUri: 'https://github.com/zerryth/security-scanner-mcp',
                        rules: Array.from(rulesMap.values()),
                    },
                },
                results,
            },
        ],
    };

    return report;
}

/**
 * SARIF 리포트를 JSON 문자열로 변환
 */
export function sarifToJSON(report: SARIFReport, pretty: boolean = true): string {
    if (pretty) {
        return JSON.stringify(report, null, 2);
    }
    return JSON.stringify(report);
}

/**
 * Rule ID 생성
 */
function generateRuleId(issue: SecurityIssue): string {
    // "SQL Injection: Unsafe query" -> "sql-injection"
    // "Hardcoded Secret: API Key" -> "hardcoded-secret-api-key"

    const colonIndex = issue.type.indexOf(':');
    let base = colonIndex > 0 ? issue.type.substring(0, colonIndex) : issue.type;

    base = base.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim();

    // CWE 또는 metadata의 ruleId가 있으면 사용
    if (issue.metadata?.ruleId) {
        return issue.metadata.ruleId;
    }

    if (issue.cweId) {
        return `${issue.cweId.toLowerCase()}-${base}`;
    }

    return base;
}

/**
 * SARIF Rule 생성
 */
function createRule(issue: SecurityIssue): SARIFRule {
    const ruleId = generateRuleId(issue);

    const rule: SARIFRule = {
        id: ruleId,
        name: issue.type,
        shortDescription: {
            text: issue.message,
        },
        fullDescription: {
            text: issue.message,
        },
        help: {
            text: issue.fix,
            markdown: `**해결책**: ${issue.fix}`,
        },
        properties: {
            tags: [],
            precision: severityToPrecision(issue.severity),
            'security-severity': severityToScore(issue.severity),
        },
    };

    // 태그 추가
    const tags: string[] = ['security'];

    if (issue.owaspCategory) {
        tags.push('owasp');
        tags.push(issue.owaspCategory.split(':')[0].toLowerCase()); // "A03:2021" -> "a03"
    }

    if (issue.cweId) {
        tags.push('cwe');
        tags.push(issue.cweId.toLowerCase());
    }

    // 타입별 태그
    const lowerType = issue.type.toLowerCase();
    if (lowerType.includes('injection')) tags.push('injection');
    if (lowerType.includes('xss')) tags.push('xss');
    if (lowerType.includes('sql')) tags.push('sql');
    if (lowerType.includes('secret') || lowerType.includes('key')) tags.push('secrets');
    if (lowerType.includes('crypto')) tags.push('cryptography');
    if (lowerType.includes('auth')) tags.push('authentication');
    if (lowerType.includes('docker')) tags.push('docker');
    if (lowerType.includes('kubernetes') || lowerType.includes('k8s')) tags.push('kubernetes');
    if (lowerType.includes('terraform')) tags.push('terraform');

    rule.properties!.tags = tags;

    return rule;
}

/**
 * SARIF Result 생성
 */
function createResult(issue: SecurityIssue, filePath?: string): SARIFResult {
    const result: SARIFResult = {
        ruleId: generateRuleId(issue),
        level: severityToLevel(issue.severity),
        message: {
            text: issue.message,
        },
    };

    // 위치 정보 추가
    if (filePath) {
        result.locations = [
            {
                physicalLocation: {
                    artifactLocation: {
                        uri: filePath,
                    },
                },
            },
        ];

        if (issue.line) {
            result.locations[0].physicalLocation.region = {
                startLine: issue.line,
            };

            if (issue.match) {
                result.locations[0].physicalLocation.region.snippet = {
                    text: issue.match,
                };
            }
        }
    }

    // 수정 방법 추가
    if (issue.fix) {
        result.fixes = [
            {
                description: {
                    text: issue.fix,
                },
            },
        ];
    }

    return result;
}

/**
 * Severity -> SARIF Level 변환
 */
function severityToLevel(severity: Severity): 'error' | 'warning' | 'note' {
    switch (severity) {
        case 'critical':
        case 'high':
            return 'error';
        case 'medium':
            return 'warning';
        case 'low':
            return 'note';
    }
}

/**
 * Severity -> Precision 변환
 */
function severityToPrecision(severity: Severity): 'very-high' | 'high' | 'medium' | 'low' {
    switch (severity) {
        case 'critical':
            return 'very-high';
        case 'high':
            return 'high';
        case 'medium':
            return 'medium';
        case 'low':
            return 'low';
    }
}

/**
 * Severity -> Security Severity Score (0.0 ~ 10.0)
 */
function severityToScore(severity: Severity): string {
    switch (severity) {
        case 'critical':
            return '9.0';
        case 'high':
            return '7.0';
        case 'medium':
            return '5.0';
        case 'low':
            return '3.0';
    }
}

/**
 * 여러 파일의 스캔 결과를 하나의 SARIF 리포트로 통합
 */
export function mergeSARIFReports(reports: SARIFReport[]): SARIFReport {
    if (reports.length === 0) {
        throw new Error('최소 1개 이상의 리포트가 필요합니다.');
    }

    if (reports.length === 1) {
        return reports[0];
    }

    const mergedReport: SARIFReport = {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [],
    };

    // 모든 runs 병합
    for (const report of reports) {
        mergedReport.runs.push(...report.runs);
    }

    return mergedReport;
}

/**
 * SARIF 리포트 통계
 */
export interface SARIFStats {
    totalIssues: number;
    errorCount: number;
    warningCount: number;
    noteCount: number;
    filesScanned: number;
    rulesTriggered: number;
}

/**
 * SARIF 리포트 통계 계산
 */
export function calculateSARIFStats(report: SARIFReport): SARIFStats {
    let totalIssues = 0;
    let errorCount = 0;
    let warningCount = 0;
    let noteCount = 0;
    const files = new Set<string>();
    const rules = new Set<string>();

    for (const run of report.runs) {
        totalIssues += run.results.length;

        for (const result of run.results) {
            rules.add(result.ruleId);

            if (result.level === 'error') errorCount++;
            else if (result.level === 'warning') warningCount++;
            else if (result.level === 'note') noteCount++;

            if (result.locations) {
                for (const loc of result.locations) {
                    files.add(loc.physicalLocation.artifactLocation.uri);
                }
            }
        }
    }

    return {
        totalIssues,
        errorCount,
        warningCount,
        noteCount,
        filesScanned: files.size,
        rulesTriggered: rules.size,
    };
}
