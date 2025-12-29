/**
 * Dockerfile 보안 스캐너
 *
 * Dockerfile의 보안 취약점을 검사합니다.
 * CIS Docker Benchmark 기반
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';
import * as fs from 'fs/promises';

interface DockerfileRule {
    id: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
    cis?: string; // CIS Docker Benchmark 참조
}

/**
 * Dockerfile 보안 규칙
 */
const DOCKERFILE_RULES: DockerfileRule[] = [
    {
        id: 'DF001',
        pattern: /^FROM\s+[^:]+$/m,
        severity: 'medium',
        message: 'Base image에 태그가 없습니다. latest는 예측 불가능합니다.',
        fix: 'FROM node:18.17.0-alpine 처럼 명시적 버전 사용',
        cis: '4.1'
    },
    {
        id: 'DF002',
        pattern: /^USER\s+root\b/m,
        severity: 'high',
        message: 'root 유저로 컨테이너를 실행합니다. 권한 상승 위험이 있습니다.',
        fix: 'USER node 등 non-root 유저 지정',
        cis: '4.3'
    },
    {
        id: 'DF003',
        pattern: /^(?!.*USER\s+(?!root))/m,
        severity: 'high',
        message: 'USER 지시어가 없습니다. 기본값인 root로 실행됩니다.',
        fix: 'Dockerfile에 USER <non-root-user> 추가',
        cis: '4.3'
    },
    {
        id: 'DF004',
        pattern: /EXPOSE\s+22\b/,
        severity: 'critical',
        message: 'SSH 포트(22) 노출은 위험합니다.',
        fix: 'SSH 대신 컨테이너 exec 사용',
        cis: '4.7'
    },
    {
        id: 'DF005',
        pattern: /apt-get\s+install(?!.*--no-install-recommends)/,
        severity: 'low',
        message: '불필요한 패키지 설치로 공격 표면 증가',
        fix: 'apt-get install --no-install-recommends 사용',
    },
    {
        id: 'DF006',
        pattern: /curl.*\|\s*(?:bash|sh)/,
        severity: 'critical',
        message: 'Pipe to shell은 중간자 공격에 취약합니다.',
        fix: '파일 다운로드 후 체크섬 검증',
    },
    {
        id: 'DF007',
        pattern: /COPY\s+--chown=\d+:\d+/,
        severity: 'low',
        message: 'Hardcoded UID/GID 사용',
        fix: '--chown=node:node 처럼 이름 사용',
        cis: '4.6'
    },
    {
        id: 'DF008',
        pattern: /ADD\s+https?:\/\//,
        severity: 'medium',
        message: 'ADD로 원격 파일 다운로드는 위험합니다.',
        fix: 'RUN wget 또는 RUN curl 사용하고 체크섬 검증',
    },
    {
        id: 'DF009',
        pattern: /apk\s+add(?!.*--no-cache)/,
        severity: 'low',
        message: 'apk 캐시가 남아 이미지 크기가 증가합니다.',
        fix: 'apk add --no-cache 사용',
    },
    {
        id: 'DF010',
        pattern: /(?:apt-get|apk|yum)\s+(?:update|upgrade)(?!.*&&)/,
        severity: 'medium',
        message: 'update와 install을 분리하면 캐시 문제가 발생합니다.',
        fix: 'RUN apt-get update && apt-get install -y ... 처럼 한 줄로',
    },
    {
        id: 'DF011',
        pattern: /HEALTHCHECK\s+NONE/,
        severity: 'medium',
        message: 'HEALTHCHECK가 비활성화되었습니다.',
        fix: 'HEALTHCHECK CMD 추가',
    },
    {
        id: 'DF012',
        pattern: /^(?!.*HEALTHCHECK)/m,
        severity: 'low',
        message: 'HEALTHCHECK가 없습니다. 컨테이너 상태 모니터링이 어렵습니다.',
        fix: 'HEALTHCHECK --interval=30s CMD <health-check-command>',
    },
    {
        id: 'DF013',
        pattern: /ENV\s+(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+/i,
        severity: 'critical',
        message: 'ENV로 민감한 정보를 설정하면 이미지에 남습니다.',
        fix: '런타임에 환경변수로 주입하세요',
    },
    {
        id: 'DF014',
        pattern: /chmod\s+777/,
        severity: 'high',
        message: '777 권한은 너무 관대합니다.',
        fix: '필요한 최소 권한만 부여 (예: 755)',
    },
    {
        id: 'DF015',
        pattern: /wget.*(?!--secure-protocol)/,
        severity: 'medium',
        message: 'wget이 안전하지 않은 프로토콜을 사용할 수 있습니다.',
        fix: 'wget --secure-protocol=TLSv1_2 사용',
    }
];

/**
 * Dockerfile 스캔
 */
export async function scanDockerfile(filePath: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    try {
        const content = await fs.readFile(filePath, 'utf-8');
        const lines = content.split('\n');

        // 각 규칙 검사
        for (const rule of DOCKERFILE_RULES) {
            // 특별 처리: USER 지시어 없음 체크
            if (rule.id === 'DF003') {
                const hasUser = /^USER\s+(?!root\b)/m.test(content);
                if (!hasUser) {
                    issues.push({
                        type: `Dockerfile: ${rule.id}`,
                        severity: rule.severity,
                        message: rule.message,
                        fix: rule.fix,
                        owaspCategory: 'A05:2021 – Security Misconfiguration',
                        cweId: 'CWE-250',
                        metadata: {
                            cisDockerBenchmark: rule.cis,
                            ruleId: rule.id
                        }
                    });
                }
                continue;
            }

            // 특별 처리: HEALTHCHECK 없음 체크
            if (rule.id === 'DF012') {
                const hasHealthcheck = /^HEALTHCHECK/m.test(content);
                if (!hasHealthcheck) {
                    issues.push({
                        type: `Dockerfile: ${rule.id}`,
                        severity: rule.severity,
                        message: rule.message,
                        fix: rule.fix,
                        owaspCategory: 'A05:2021 – Security Misconfiguration',
                        metadata: {
                            cisDockerBenchmark: rule.cis,
                            ruleId: rule.id
                        }
                    });
                }
                continue;
            }

            // 일반 패턴 매칭
            rule.pattern.lastIndex = 0;
            const matches = content.matchAll(new RegExp(rule.pattern, 'gm'));

            for (const match of matches) {
                const lineNumber = findLineNumber(content, match.index || 0);
                const line = lines[lineNumber - 1];

                // 주석 스킵
                if (line && line.trim().startsWith('#')) {
                    continue;
                }

                issues.push({
                    type: `Dockerfile: ${rule.id}`,
                    severity: rule.severity,
                    message: rule.message,
                    fix: rule.fix,
                    line: lineNumber,
                    match: line?.trim(),
                    owaspCategory: 'A05:2021 – Security Misconfiguration',
                    cweId: 'CWE-732',
                    metadata: {
                        cisDockerBenchmark: rule.cis,
                        ruleId: rule.id
                    }
                });
            }
        }

        // 추가 보안 체크
        issues.push(...checkMultiStageBuilds(content));
        issues.push(...checkCopyVsAdd(content, lines));

    } catch (error) {
        console.error(`Dockerfile 스캔 실패 (${filePath}):`, error);
    }

    return issues;
}

/**
 * Multi-stage build 사용 여부 체크
 */
function checkMultiStageBuilds(content: string): SecurityIssue[] {
    const fromCount = (content.match(/^FROM/gm) || []).length;

    // FROM이 1개뿐이고 production용 이미지인 경우 경고
    if (fromCount === 1 && /COPY|ADD/i.test(content)) {
        return [{
            type: 'Dockerfile: Best Practice',
            severity: 'low',
            message: 'Multi-stage build를 사용하면 최종 이미지 크기를 줄일 수 있습니다.',
            fix: 'Multi-stage build 패턴 사용 (빌드 단계와 실행 단계 분리)',
            owaspCategory: 'A05:2021 – Security Misconfiguration',
        }];
    }

    return [];
}

/**
 * COPY vs ADD 사용 패턴 체크
 */
function checkCopyVsAdd(content: string, lines: string[]): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    lines.forEach((line, idx) => {
        const trimmed = line.trim();

        // ADD를 COPY로 바꿀 수 있는 경우
        if (trimmed.startsWith('ADD ') && !trimmed.match(/\.tar|\.tgz|\.tar\.gz|https?:\/\//)) {
            issues.push({
                type: 'Dockerfile: Best Practice',
                severity: 'low',
                message: 'ADD 대신 COPY를 사용하세요. ADD는 압축 해제 등 추가 기능이 있어 예측하기 어렵습니다.',
                fix: 'COPY 사용',
                line: idx + 1,
                match: trimmed,
            });
        }
    });

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
 * Dockerfile 스캔 결과 포맷팅
 */
export function formatDockerfileScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ Dockerfile 보안 검사 통과!

발견된 보안 취약점이 없습니다.`;
    }

    let result = `## 🐳 Dockerfile 보안 취약점 발견!

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

    result += `\n---\n\n**참고**: [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)`;

    return result;
}

function formatIssueList(issues: SecurityIssue[]): string {
    return issues.map(issue => `
- **${issue.type}**${issue.line ? ` (라인 ${issue.line})` : ''}
  - ${issue.message}
  - 💡 해결책: ${issue.fix}
${issue.metadata?.cisDockerBenchmark ? `  - 📖 CIS Benchmark: ${issue.metadata.cisDockerBenchmark}` : ''}
`).join('') + '\n';
}
