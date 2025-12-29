/**
 * Markdown 리포트 생성기
 *
 * 보안 스캔 결과를 보기 좋은 Markdown 형식으로 변환합니다.
 *
 * @author zerry
 */

import { SecurityIssue, Severity } from '../types.js';

export interface ReportOptions {
    includeSummary?: boolean;
    includeDetails?: boolean;
    groupBy?: 'severity' | 'category' | 'file';
    showRecommendations?: boolean;
}

/**
 * 보안 스캔 결과를 Markdown 리포트로 생성
 */
export function generateMarkdownReport(
    issues: SecurityIssue[],
    options: ReportOptions = {}
): string {
    const {
        includeSummary = true,
        includeDetails = true,
        groupBy = 'severity',
        showRecommendations = true,
    } = options;

    let report = `# 🔒 보안 스캔 리포트\n\n`;
    report += `**스캔 일시**: ${new Date().toLocaleString('ko-KR')}\n`;
    report += `**총 발견 취약점**: ${issues.length}개\n\n`;

    if (issues.length === 0) {
        return report + `## ✅ 취약점 없음\n\n훌륭합니다! 발견된 보안 취약점이 없습니다.\n`;
    }

    // 요약 통계
    if (includeSummary) {
        report += generateSummarySection(issues);
    }

    // 상세 내용
    if (includeDetails) {
        report += generateDetailsSection(issues, groupBy);
    }

    // 권장 조치
    if (showRecommendations) {
        report += generateRecommendationsSection(issues);
    }

    return report;
}

/**
 * 요약 통계 섹션 생성
 */
function generateSummarySection(issues: SecurityIssue[]): string {
    const summary = {
        critical: issues.filter(i => i.severity === 'critical').length,
        high: issues.filter(i => i.severity === 'high').length,
        medium: issues.filter(i => i.severity === 'medium').length,
        low: issues.filter(i => i.severity === 'low').length,
    };

    const total = issues.length;

    let section = `## 📊 요약 통계\n\n`;
    section += `| 심각도 | 개수 | 비율 | 진행 바 |\n`;
    section += `|--------|------|------|----------|\n`;
    section += `| 🔴 **Critical** | ${summary.critical} | ${((summary.critical / total) * 100).toFixed(1)}% | ${generateProgressBar(summary.critical, total, 'red')} |\n`;
    section += `| 🟠 **High** | ${summary.high} | ${((summary.high / total) * 100).toFixed(1)}% | ${generateProgressBar(summary.high, total, 'orange')} |\n`;
    section += `| 🟡 **Medium** | ${summary.medium} | ${((summary.medium / total) * 100).toFixed(1)}% | ${generateProgressBar(summary.medium, total, 'yellow')} |\n`;
    section += `| 🟢 **Low** | ${summary.low} | ${((summary.low / total) * 100).toFixed(1)}% | ${generateProgressBar(summary.low, total, 'green')} |\n`;
    section += `| **전체** | **${total}** | **100.0%** | ${generateProgressBar(total, total, 'blue')} |\n\n`;

    // OWASP 카테고리별 통계
    const owaspStats = getOWASPStatistics(issues);
    if (owaspStats.size > 0) {
        section += `### OWASP Top 10 분포\n\n`;
        section += `| OWASP 카테고리 | 개수 |\n`;
        section += `|---------------|------|\n`;

        for (const [category, count] of Array.from(owaspStats.entries()).sort((a, b) => b[1] - a[1])) {
            section += `| ${category} | ${count} |\n`;
        }
        section += `\n`;
    }

    return section;
}

/**
 * 상세 내용 섹션 생성
 */
function generateDetailsSection(
    issues: SecurityIssue[],
    groupBy: 'severity' | 'category' | 'file'
): string {
    let section = `## 📋 상세 내용\n\n`;

    if (groupBy === 'severity') {
        section += generateBySeverity(issues);
    } else if (groupBy === 'category') {
        section += generateByCategory(issues);
    }

    return section;
}

/**
 * 심각도별 그룹화
 */
function generateBySeverity(issues: SecurityIssue[]): string {
    let output = '';

    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];

    for (const severity of severities) {
        const filtered = issues.filter(i => i.severity === severity);
        if (filtered.length === 0) continue;

        const emoji = getSeverityEmoji(severity);
        output += `### ${emoji} ${severity.toUpperCase()} (${filtered.length}개)\n\n`;
        output += generateIssueTable(filtered);
        output += `\n`;
    }

    return output;
}

/**
 * 카테고리별 그룹화
 */
function generateByCategory(issues: SecurityIssue[]): string {
    let output = '';

    const categories = new Map<string, SecurityIssue[]>();

    for (const issue of issues) {
        const category = issue.owaspCategory || 'Others';
        if (!categories.has(category)) {
            categories.set(category, []);
        }
        categories.get(category)!.push(issue);
    }

    for (const [category, categoryIssues] of categories.entries()) {
        output += `### ${category} (${categoryIssues.length}개)\n\n`;
        output += generateIssueTable(categoryIssues);
        output += `\n`;
    }

    return output;
}

/**
 * 이슈 테이블 생성
 */
function generateIssueTable(issues: SecurityIssue[]): string {
    let table = `| 심각도 | 타입 | 위치 | 메시지 |\n`;
    table += `|--------|------|------|--------|\n`;

    for (const issue of issues) {
        const emoji = getSeverityEmoji(issue.severity);
        const location = issue.line ? `라인 ${issue.line}` : '-';
        const message = truncate(issue.message, 60);

        table += `| ${emoji} ${issue.severity} | ${issue.type} | ${location} | ${message} |\n`;
    }

    return table;
}

/**
 * 권장 조치 섹션 생성
 */
function generateRecommendationsSection(issues: SecurityIssue[]): string {
    let section = `## 💡 우선 조치 권장사항\n\n`;

    // Critical 이슈 먼저
    const critical = issues.filter(i => i.severity === 'critical');
    if (critical.length > 0) {
        section += `### 🚨 즉시 조치 필요 (Critical)\n\n`;
        section += `이 취약점들은 **즉각적인 보안 위협**입니다. 우선적으로 수정해주세요.\n\n`;

        critical.slice(0, 5).forEach((issue, idx) => {
            section += `${idx + 1}. **${issue.type}**`;
            if (issue.line) section += ` (라인 ${issue.line})`;
            section += `\n`;
            section += `   - 📌 **문제**: ${issue.message}\n`;
            section += `   - ✅ **해결**: ${issue.fix}\n`;
            if (issue.cweId) section += `   - 🔗 **참고**: [${issue.cweId}](https://cwe.mitre.org/data/definitions/${issue.cweId.replace('CWE-', '')}.html)\n`;
            section += `\n`;
        });

        if (critical.length > 5) {
            section += `_... 외 ${critical.length - 5}개의 Critical 이슈가 더 있습니다._\n\n`;
        }
    }

    // High 이슈
    const high = issues.filter(i => i.severity === 'high');
    if (high.length > 0) {
        section += `### 🟠 높은 우선순위 (High)\n\n`;
        section += `다음 ${high.length}개의 High 이슈도 빠르게 수정이 필요합니다.\n\n`;

        high.slice(0, 3).forEach((issue, idx) => {
            section += `- **${issue.type}**`;
            if (issue.line) section += ` (라인 ${issue.line})`;
            section += `: ${truncate(issue.message, 80)}\n`;
        });

        if (high.length > 3) {
            section += `- _... 외 ${high.length - 3}개_\n`;
        }
        section += `\n`;
    }

    // 일반적인 보안 권장사항
    section += `### 🛡️ 일반 보안 권장사항\n\n`;
    section += `1. **정기적인 의존성 업데이트**: \`npm audit\`, \`npm update\` 실행\n`;
    section += `2. **환경 변수 사용**: 시크릿은 절대 코드에 하드코딩하지 마세요\n`;
    section += `3. **입력 검증**: 모든 사용자 입력을 검증하고 sanitize하세요\n`;
    section += `4. **최소 권한 원칙**: 필요한 최소한의 권한만 부여하세요\n`;
    section += `5. **보안 헤더 설정**: CSP, X-Frame-Options 등을 설정하세요\n\n`;

    return section;
}

/**
 * 진행 바 생성 (Unicode 블록 사용)
 */
function generateProgressBar(value: number, max: number, color: string = 'blue'): string {
    const barLength = 10;
    const filled = Math.round((value / max) * barLength);
    const empty = barLength - filled;

    const filledChar = '█';
    const emptyChar = '░';

    return filledChar.repeat(filled) + emptyChar.repeat(empty);
}

/**
 * 심각도별 이모지
 */
function getSeverityEmoji(severity: Severity): string {
    switch (severity) {
        case 'critical': return '🔴';
        case 'high': return '🟠';
        case 'medium': return '🟡';
        case 'low': return '🟢';
        default: return '⚪';
    }
}

/**
 * OWASP 통계 계산
 */
function getOWASPStatistics(issues: SecurityIssue[]): Map<string, number> {
    const stats = new Map<string, number>();

    for (const issue of issues) {
        if (issue.owaspCategory) {
            const count = stats.get(issue.owaspCategory) || 0;
            stats.set(issue.owaspCategory, count + 1);
        }
    }

    return stats;
}

/**
 * 문자열 자르기
 */
function truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.slice(0, maxLength - 3) + '...';
}

/**
 * 간단한 요약 생성
 */
export function generateQuickSummary(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return '✅ 발견된 취약점 없음';
    }

    const critical = issues.filter(i => i.severity === 'critical').length;
    const high = issues.filter(i => i.severity === 'high').length;

    let summary = `⚠️ ${issues.length}개 취약점 발견`;

    if (critical > 0) {
        summary += ` (🔴 Critical: ${critical}개`;
        if (high > 0) summary += `, 🟠 High: ${high}개`;
        summary += ')';
    } else if (high > 0) {
        summary += ` (🟠 High: ${high}개)`;
    }

    return summary;
}
