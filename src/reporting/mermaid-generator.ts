/**
 * Mermaid 다이어그램 생성기
 *
 * 보안 스캔 결과를 시각화하는 Mermaid 다이어그램을 생성합니다.
 * - Pie Chart: 취약점 타입별 분포
 * - Bar Chart: 심각도별 통계
 * - Flowchart: 공격 시나리오 흐름도
 *
 * @author zerry
 */

import { SecurityIssue, Severity } from '../types.js';

/**
 * Mermaid 차트 타입
 */
export type MermaidChartType = 'pie' | 'bar' | 'flowchart';

/**
 * 심각도별 취약점 개수 파이 차트 생성
 */
export function generateSeverityPieChart(issues: SecurityIssue[]): string {
    const severityCounts = new Map<Severity, number>();

    for (const issue of issues) {
        const count = severityCounts.get(issue.severity) || 0;
        severityCounts.set(issue.severity, count + 1);
    }

    let chart = '```mermaid\npie title 심각도별 취약점 분포\n';

    // 심각도 순서대로 출력
    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
    for (const severity of severities) {
        const count = severityCounts.get(severity) || 0;
        if (count > 0) {
            const label = getSeverityLabel(severity);
            chart += `    "${label}" : ${count}\n`;
        }
    }

    chart += '```';
    return chart;
}

/**
 * 취약점 타입별 분포 파이 차트 생성
 */
export function generateTypePieChart(issues: SecurityIssue[]): string {
    const typeCounts = new Map<string, number>();

    for (const issue of issues) {
        // 타입 간소화 (예: "SQL Injection: Unsafe query" -> "SQL Injection")
        const simpleType = simplifyType(issue.type);
        const count = typeCounts.get(simpleType) || 0;
        typeCounts.set(simpleType, count + 1);
    }

    // 상위 8개만 표시, 나머지는 "기타"로 묶음
    const sorted = Array.from(typeCounts.entries())
        .sort((a, b) => b[1] - a[1]);

    let chart = '```mermaid\npie title 취약점 타입별 분포\n';

    const topN = sorted.slice(0, 8);
    const others = sorted.slice(8);

    for (const [type, count] of topN) {
        chart += `    "${type}" : ${count}\n`;
    }

    if (others.length > 0) {
        const othersCount = others.reduce((sum, [, count]) => sum + count, 0);
        chart += `    "기타 (${others.length}개 타입)" : ${othersCount}\n`;
    }

    chart += '```';
    return chart;
}

/**
 * OWASP 카테고리별 분포 파이 차트 생성
 */
export function generateOWASPPieChart(issues: SecurityIssue[]): string {
    const owaspCounts = new Map<string, number>();

    for (const issue of issues) {
        if (issue.owaspCategory) {
            const count = owaspCounts.get(issue.owaspCategory) || 0;
            owaspCounts.set(issue.owaspCategory, count + 1);
        }
    }

    if (owaspCounts.size === 0) {
        return '';
    }

    const sorted = Array.from(owaspCounts.entries())
        .sort((a, b) => b[1] - a[1]);

    let chart = '```mermaid\npie title OWASP Top 10 분포\n';

    for (const [category, count] of sorted) {
        // "A03:2021 – Injection" -> "A03 Injection"
        const shortName = category.replace(/:\d{4}/, '').replace('–', '').trim();
        chart += `    "${shortName}" : ${count}\n`;
    }

    chart += '```';
    return chart;
}

/**
 * 심각도별 통계 바 차트 생성 (Horizontal Bar)
 */
export function generateSeverityBarChart(issues: SecurityIssue[]): string {
    const severityCounts = new Map<Severity, number>();

    for (const issue of issues) {
        const count = severityCounts.get(issue.severity) || 0;
        severityCounts.set(issue.severity, count + 1);
    }

    let chart = '```mermaid\n%%{init: {"theme": "dark", "themeVariables": {"primaryColor": "#ff6b6b"}}}%%\n';
    chart += 'graph LR\n';

    const critical = severityCounts.get('critical') || 0;
    const high = severityCounts.get('high') || 0;
    const medium = severityCounts.get('medium') || 0;
    const low = severityCounts.get('low') || 0;

    if (critical > 0) {
        chart += `    A[🔴 Critical] -->|${critical}개| B((${critical}))\n`;
        chart += '    style A fill:#c92a2a,stroke:#c92a2a,color:#fff\n';
        chart += '    style B fill:#c92a2a,stroke:#c92a2a,color:#fff\n';
    }

    if (high > 0) {
        chart += `    C[🟠 High] -->|${high}개| D((${high}))\n`;
        chart += '    style C fill:#f76707,stroke:#f76707,color:#fff\n';
        chart += '    style D fill:#f76707,stroke:#f76707,color:#fff\n';
    }

    if (medium > 0) {
        chart += `    E[🟡 Medium] -->|${medium}개| F((${medium}))\n`;
        chart += '    style E fill:#fab005,stroke:#fab005,color:#000\n';
        chart += '    style F fill:#fab005,stroke:#fab005,color:#000\n';
    }

    if (low > 0) {
        chart += `    G[🟢 Low] -->|${low}개| H((${low}))\n`;
        chart += '    style G fill:#37b24d,stroke:#37b24d,color:#fff\n';
        chart += '    style H fill:#37b24d,stroke:#37b24d,color:#fff\n';
    }

    chart += '```';
    return chart;
}

/**
 * 공격 시나리오 플로우차트 생성
 *
 * 주요 취약점을 기반으로 가능한 공격 경로를 시각화합니다.
 */
export function generateAttackFlowchart(issues: SecurityIssue[]): string {
    const hasInjection = issues.some(i => i.type.toLowerCase().includes('injection'));
    const hasXSS = issues.some(i => i.type.toLowerCase().includes('xss'));
    const hasAuth = issues.some(i => i.type.toLowerCase().includes('auth'));
    const hasSecrets = issues.some(i => i.type.toLowerCase().includes('secret') || i.type.toLowerCase().includes('key'));
    const hasCrypto = issues.some(i => i.type.toLowerCase().includes('crypto') || i.type.toLowerCase().includes('md5') || i.type.toLowerCase().includes('sha1'));

    if (!hasInjection && !hasXSS && !hasAuth && !hasSecrets && !hasCrypto) {
        return '';
    }

    let chart = '```mermaid\nflowchart TD\n';
    chart += '    Start([공격자]) --> Recon[정찰]\n';

    const attacks: string[] = [];

    if (hasSecrets) {
        chart += '    Recon --> Secrets[하드코딩된<br/>시크릿 발견]\n';
        chart += '    Secrets --> Access1[인증 우회]\n';
        attacks.push('Access1');
    }

    if (hasAuth) {
        chart += '    Recon --> AuthBypass[인증 취약점<br/>발견]\n';
        chart += '    AuthBypass --> Access2[무단 접근]\n';
        attacks.push('Access2');
    }

    if (hasInjection) {
        chart += '    Recon --> SQLi[SQL Injection<br/>취약점 발견]\n';
        chart += '    SQLi --> DBAccess[데이터베이스<br/>접근]\n';
        chart += '    DBAccess --> DataExfil[민감 데이터<br/>유출]\n';
        attacks.push('DataExfil');
    }

    if (hasXSS) {
        chart += '    Recon --> XSS[XSS 취약점<br/>발견]\n';
        chart += '    XSS --> SessionHijack[세션 탈취]\n';
        attacks.push('SessionHijack');
    }

    if (hasCrypto) {
        chart += '    Recon --> WeakCrypto[취약한 암호화<br/>발견]\n';
        chart += '    WeakCrypto --> Decrypt[암호 해독]\n';
        attacks.push('Decrypt');
    }

    // 모든 공격이 최종 목표로 수렴
    for (const attack of attacks) {
        chart += `    ${attack} --> Impact[시스템 장악]\n`;
    }

    chart += '    Impact --> End([공격 성공])\n\n';

    // 스타일링
    chart += '    style Start fill:#e3fafc,stroke:#0c8599\n';
    chart += '    style Recon fill:#fff3bf,stroke:#f59f00\n';
    chart += '    style Impact fill:#ffe0e0,stroke:#c92a2a\n';
    chart += '    style End fill:#ffe0e0,stroke:#c92a2a\n';

    if (hasSecrets) {
        chart += '    style Secrets fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style Access1 fill:#ffc9c9,stroke:#c92a2a\n';
    }

    if (hasAuth) {
        chart += '    style AuthBypass fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style Access2 fill:#ffc9c9,stroke:#c92a2a\n';
    }

    if (hasInjection) {
        chart += '    style SQLi fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style DBAccess fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style DataExfil fill:#ffc9c9,stroke:#c92a2a\n';
    }

    if (hasXSS) {
        chart += '    style XSS fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style SessionHijack fill:#ffc9c9,stroke:#c92a2a\n';
    }

    if (hasCrypto) {
        chart += '    style WeakCrypto fill:#ffc9c9,stroke:#c92a2a\n';
        chart += '    style Decrypt fill:#ffc9c9,stroke:#c92a2a\n';
    }

    chart += '```';
    return chart;
}

/**
 * 스캔 결과 종합 대시보드 생성
 */
export function generateSecurityDashboard(issues: SecurityIssue[]): string {
    let dashboard = '# 🛡️ 보안 스캔 대시보드\n\n';

    // 1. 전체 요약
    dashboard += `## 📊 전체 요약\n\n`;
    dashboard += `총 **${issues.length}개**의 취약점이 발견되었습니다.\n\n`;

    // 2. 심각도별 파이 차트
    dashboard += `## 🎯 심각도별 분포\n\n`;
    dashboard += generateSeverityPieChart(issues);
    dashboard += '\n\n';

    // 3. 타입별 파이 차트
    dashboard += `## 📋 취약점 타입별 분포\n\n`;
    dashboard += generateTypePieChart(issues);
    dashboard += '\n\n';

    // 4. OWASP 카테고리 파이 차트
    const owaspChart = generateOWASPPieChart(issues);
    if (owaspChart) {
        dashboard += `## 🏆 OWASP Top 10 분포\n\n`;
        dashboard += owaspChart;
        dashboard += '\n\n';
    }

    // 5. 공격 시나리오
    const attackFlow = generateAttackFlowchart(issues);
    if (attackFlow) {
        dashboard += `## ⚔️ 가능한 공격 시나리오\n\n`;
        dashboard += attackFlow;
        dashboard += '\n\n';
    }

    // 6. 우선순위 권장사항
    dashboard += `## 🚨 우선 조치 권장사항\n\n`;

    const critical = issues.filter(i => i.severity === 'critical');
    const high = issues.filter(i => i.severity === 'high');

    if (critical.length > 0) {
        dashboard += `### 🔴 Critical (${critical.length}개)\n\n`;
        dashboard += '즉시 수정이 필요합니다:\n\n';

        for (const issue of critical.slice(0, 5)) {
            dashboard += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
            dashboard += `  - ${issue.message}\n`;
        }

        if (critical.length > 5) {
            dashboard += `\n... 외 ${critical.length - 5}개\n`;
        }
        dashboard += '\n';
    }

    if (high.length > 0) {
        dashboard += `### 🟠 High (${high.length}개)\n\n`;
        dashboard += '우선적으로 수정이 필요합니다:\n\n';

        for (const issue of high.slice(0, 3)) {
            dashboard += `- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}\n`;
        }

        if (high.length > 3) {
            dashboard += `\n... 외 ${high.length - 3}개\n`;
        }
        dashboard += '\n';
    }

    return dashboard;
}

/**
 * 헬퍼: 심각도 레이블
 */
function getSeverityLabel(severity: Severity): string {
    const labels = {
        critical: '🔴 Critical',
        high: '🟠 High',
        medium: '🟡 Medium',
        low: '🟢 Low'
    };
    return labels[severity];
}

/**
 * 헬퍼: 타입 이름 간소화
 */
function simplifyType(type: string): string {
    // "SQL Injection: Unsafe query" -> "SQL Injection"
    // "Hardcoded Secret: API Key" -> "Hardcoded Secret"
    const colonIndex = type.indexOf(':');
    if (colonIndex > 0) {
        return type.substring(0, colonIndex).trim();
    }
    return type;
}
