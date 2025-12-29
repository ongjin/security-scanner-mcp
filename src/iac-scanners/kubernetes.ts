/**
 * Kubernetes YAML 보안 스캐너
 *
 * Kubernetes 매니페스트의 보안 취약점을 검사합니다.
 * Pod Security Standards (PSS) 및 CIS Kubernetes Benchmark 기반
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';
import * as yaml from 'js-yaml';
import * as fs from 'fs/promises';

interface K8sSecurityCheck {
    id: string;
    path: string; // YAML 경로 (예: "spec.containers[*].securityContext")
    condition: (value: any) => boolean;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
    pss?: 'restricted' | 'baseline'; // Pod Security Standards 레벨
}

/**
 * Kubernetes 보안 규칙
 */
const K8S_SECURITY_CHECKS: K8sSecurityCheck[] = [
    {
        id: 'K8S001',
        path: 'spec.containers[*].securityContext.privileged',
        condition: (val) => val === true,
        severity: 'critical',
        message: 'Privileged 컨테이너는 호스트의 모든 권한을 가집니다.',
        fix: 'privileged: false 설정 또는 제거',
        pss: 'baseline'
    },
    {
        id: 'K8S002',
        path: 'spec.containers[*].securityContext.runAsNonRoot',
        condition: (val) => val !== true,
        severity: 'high',
        message: 'Root로 컨테이너 실행 가능',
        fix: 'runAsNonRoot: true 설정',
        pss: 'restricted'
    },
    {
        id: 'K8S003',
        path: 'spec.hostNetwork',
        condition: (val) => val === true,
        severity: 'high',
        message: 'Host 네트워크 사용은 격리를 우회합니다.',
        fix: 'hostNetwork 제거 또는 false 설정',
        pss: 'baseline'
    },
    {
        id: 'K8S004',
        path: 'spec.hostPID',
        condition: (val) => val === true,
        severity: 'high',
        message: 'Host PID 네임스페이스 사용은 위험합니다.',
        fix: 'hostPID 제거',
        pss: 'baseline'
    },
    {
        id: 'K8S005',
        path: 'spec.hostIPC',
        condition: (val) => val === true,
        severity: 'high',
        message: 'Host IPC 네임스페이스 사용은 위험합니다.',
        fix: 'hostIPC 제거',
        pss: 'baseline'
    },
    {
        id: 'K8S006',
        path: 'spec.containers[*].securityContext.capabilities.add',
        condition: (val) => Array.isArray(val) && val.some(c => ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE'].includes(c)),
        severity: 'critical',
        message: '위험한 Linux capability가 추가되었습니다.',
        fix: '필요한 최소 capability만 추가',
        pss: 'baseline'
    },
    {
        id: 'K8S007',
        path: 'spec.containers[*].resources.limits',
        condition: (val) => !val || (!val.memory && !val.cpu),
        severity: 'medium',
        message: 'Resource limit 없음 → DoS 위험',
        fix: 'resources.limits.cpu와 memory 설정',
    },
    {
        id: 'K8S008',
        path: 'spec.containers[*].securityContext.allowPrivilegeEscalation',
        condition: (val) => val === true,
        severity: 'high',
        message: 'Privilege escalation이 허용되었습니다.',
        fix: 'allowPrivilegeEscalation: false 설정',
        pss: 'restricted'
    },
    {
        id: 'K8S009',
        path: 'spec.containers[*].securityContext.readOnlyRootFilesystem',
        condition: (val) => val !== true,
        severity: 'medium',
        message: 'Root 파일시스템이 쓰기 가능합니다.',
        fix: 'readOnlyRootFilesystem: true 설정',
        pss: 'restricted'
    },
    {
        id: 'K8S010',
        path: 'spec.volumes[*].hostPath',
        condition: (val) => val !== undefined,
        severity: 'high',
        message: 'hostPath 볼륨은 호스트 파일시스템에 접근합니다.',
        fix: 'PVC, ConfigMap, Secret 등 다른 볼륨 타입 사용',
        pss: 'baseline'
    },
    {
        id: 'K8S011',
        path: 'spec.containers[*].image',
        condition: (val) => typeof val === 'string' && !val.includes(':'),
        severity: 'medium',
        message: '이미지 태그가 명시되지 않았습니다 (latest 사용).',
        fix: '명시적인 버전 태그 사용 (예: nginx:1.21.0)',
    },
    {
        id: 'K8S012',
        path: 'spec.containers[*].image',
        condition: (val) => typeof val === 'string' && val.endsWith(':latest'),
        severity: 'medium',
        message: ':latest 태그는 예측 불가능합니다.',
        fix: '명시적인 버전 태그 사용',
    },
    {
        id: 'K8S013',
        path: 'metadata.namespace',
        condition: (val) => val === 'default',
        severity: 'low',
        message: 'default 네임스페이스 사용',
        fix: '전용 네임스페이스 생성 및 사용',
    },
];

/**
 * Kubernetes YAML 스캔
 */
export async function scanKubernetes(filePath: string): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];

    try {
        const content = await fs.readFile(filePath, 'utf-8');

        // YAML 파싱 (멀티 문서 지원)
        const docs = yaml.loadAll(content) as any[];

        for (const doc of docs) {
            if (!doc || typeof doc !== 'object') continue;

            // Pod, Deployment, StatefulSet, DaemonSet만 검사
            const kind = doc.kind;
            if (!['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob'].includes(kind)) {
                continue;
            }

            // 각 보안 규칙 검사
            for (const check of K8S_SECURITY_CHECKS) {
                const violations = extractValues(doc, check.path);

                for (const { value, path: actualPath } of violations) {
                    if (check.condition(value)) {
                        issues.push({
                            type: `Kubernetes: ${check.id}`,
                            severity: check.severity,
                            message: check.message,
                            fix: check.fix,
                            match: `${actualPath}: ${JSON.stringify(value)}`,
                            owaspCategory: 'A05:2021 – Security Misconfiguration',
                            cweId: 'CWE-250',
                            metadata: {
                                kind: doc.kind,
                                name: doc.metadata?.name,
                                namespace: doc.metadata?.namespace,
                                pss: check.pss,
                                ruleId: check.id,
                                path: actualPath
                            }
                        });
                    }
                }
            }

            // 추가 보안 체크
            issues.push(...checkServiceAccount(doc));
            issues.push(...checkSecrets(doc));
            issues.push(...checkNetworkPolicies(doc));
        }

    } catch (error) {
        console.error(`Kubernetes YAML 스캔 실패 (${filePath}):`, error);
    }

    return issues;
}

/**
 * YAML 경로에서 값 추출 (JSONPath 스타일)
 */
function extractValues(obj: any, path: string): Array<{ value: any; path: string }> {
    const results: Array<{ value: any; path: string }> = [];
    const parts = path.split('.');

    function traverse(current: any, currentPath: string[], depth: number) {
        if (depth >= parts.length) {
            results.push({
                value: current,
                path: currentPath.join('.')
            });
            return;
        }

        const part = parts[depth];

        // 배열 처리 (예: containers[*])
        if (part.includes('[*]')) {
            const key = part.replace('[*]', '');
            if (current[key] && Array.isArray(current[key])) {
                current[key].forEach((item: any, idx: number) => {
                    traverse(item, [...currentPath, `${key}[${idx}]`], depth + 1);
                });
            }
        } else if (current[part] !== undefined) {
            traverse(current[part], [...currentPath, part], depth + 1);
        }
    }

    traverse(obj, [], 0);
    return results;
}

/**
 * ServiceAccount 보안 체크
 */
function checkServiceAccount(manifest: any): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // automountServiceAccountToken 체크
    if (manifest.spec?.automountServiceAccountToken === true) {
        issues.push({
            type: 'Kubernetes: ServiceAccount',
            severity: 'medium',
            message: 'Service Account 토큰이 자동으로 마운트됩니다.',
            fix: 'automountServiceAccountToken: false 설정 (필요하지 않은 경우)',
            owaspCategory: 'A07:2021 – Identification and Authentication Failures',
            metadata: {
                kind: manifest.kind,
                name: manifest.metadata?.name,
            }
        });
    }

    return issues;
}

/**
 * Secret 관련 보안 체크
 */
function checkSecrets(manifest: any): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Secret이 환경변수로 노출되는지 체크
    const containers = manifest.spec?.containers || [];

    for (const container of containers) {
        const env = container.env || [];

        for (const envVar of env) {
            if (envVar.valueFrom?.secretKeyRef) {
                // 이건 괜찮음 (Secret 참조)
                continue;
            }

            // 평문 환경변수에서 시크릿 패턴 체크
            if (envVar.value && /password|secret|token|api[_-]?key/i.test(envVar.name)) {
                issues.push({
                    type: 'Kubernetes: Hardcoded Secret',
                    severity: 'critical',
                    message: `환경변수 ${envVar.name}에 평문 값이 설정되었습니다.`,
                    fix: 'Secret 리소스를 생성하고 secretKeyRef로 참조',
                    owaspCategory: 'A02:2021 – Cryptographic Failures',
                    cweId: 'CWE-798',
                    metadata: {
                        containerName: container.name,
                        envVarName: envVar.name,
                    }
                });
            }
        }
    }

    return issues;
}

/**
 * NetworkPolicy 체크
 */
function checkNetworkPolicies(manifest: any): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Deployment/Pod인데 NetworkPolicy selector가 없는 경우 경고
    if (['Deployment', 'StatefulSet', 'Pod'].includes(manifest.kind)) {
        // 이건 실제로는 클러스터 전체를 봐야 하지만,
        // 여기서는 간단히 경고만
        issues.push({
            type: 'Kubernetes: Best Practice',
            severity: 'low',
            message: 'NetworkPolicy로 네트워크 트래픽을 제한하는 것을 권장합니다.',
            fix: 'NetworkPolicy 리소스 생성하여 ingress/egress 규칙 정의',
            owaspCategory: 'A05:2021 – Security Misconfiguration',
            metadata: {
                kind: manifest.kind,
                name: manifest.metadata?.name,
            }
        });
    }

    return issues;
}

/**
 * Kubernetes 스캔 결과 포맷팅
 */
export function formatKubernetesScanResult(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
        return `## ✅ Kubernetes YAML 보안 검사 통과!

발견된 보안 취약점이 없습니다.`;
    }

    let result = `## ⎈ Kubernetes YAML 보안 취약점 발견!

총 **${issues.length}개**의 취약점이 발견되었습니다.

`;

    // Pod Security Standards 요약
    const pssIssues = issues.filter(i => i.metadata?.pss);
    if (pssIssues.length > 0) {
        const baseline = pssIssues.filter(i => i.metadata?.pss === 'baseline').length;
        const restricted = pssIssues.filter(i => i.metadata?.pss === 'restricted').length;

        result += `### 📊 Pod Security Standards 위반\n\n`;
        result += `- 🔴 **Baseline** 위반: ${baseline}개\n`;
        result += `- 🟠 **Restricted** 위반: ${restricted}개\n\n`;
    }

    // 심각도별 분류
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

    result += `\n---\n\n`;
    result += `**참고 자료**:\n`;
    result += `- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)\n`;
    result += `- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)\n`;

    return result;
}

function formatIssueList(issues: SecurityIssue[]): string {
    return issues.map(issue => {
        let output = `- **${issue.type}**`;

        if (issue.metadata?.kind && issue.metadata?.name) {
            output += ` (${issue.metadata.kind}/${issue.metadata.name})`;
        }

        output += `\n`;
        output += `  - ${issue.message}\n`;
        output += `  - 💡 해결책: ${issue.fix}\n`;

        if (issue.metadata?.pss) {
            output += `  - 🏷️ PSS: ${issue.metadata.pss}\n`;
        }

        return output;
    }).join('\n') + '\n';
}
