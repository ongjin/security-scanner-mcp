/**
 * IaC 스캐너 통합 모듈
 *
 * Dockerfile, Kubernetes, Terraform 등 IaC 파일을 감지하고 적절한 스캐너를 실행합니다.
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';
import { scanDockerfile, formatDockerfileScanResult } from './dockerfile.js';
import { scanKubernetes, formatKubernetesScanResult } from './kubernetes.js';
import { scanTerraform, formatTerraformScanResult } from './terraform.js';
import * as path from 'path';

export type IaCType = 'dockerfile' | 'kubernetes' | 'terraform' | 'unknown';

/**
 * 파일 경로에서 IaC 타입 감지
 */
export function detectIaCType(filePath: string): IaCType {
    const basename = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();

    // Dockerfile
    if (basename === 'dockerfile' || basename.startsWith('dockerfile.')) {
        return 'dockerfile';
    }

    // Kubernetes YAML
    if (['.yaml', '.yml'].includes(ext)) {
        // 내용을 보지 않고 파일명으로 추측
        if (basename.includes('deployment') ||
            basename.includes('pod') ||
            basename.includes('service') ||
            basename.includes('k8s') ||
            basename.includes('kube')) {
            return 'kubernetes';
        }
        // 기본적으로 kubernetes로 시도 (yaml은 보통 k8s에서 많이 사용)
        return 'kubernetes';
    }

    // Terraform
    if (ext === '.tf' || ext === '.tfvars') {
        return 'terraform';
    }

    return 'unknown';
}

/**
 * IaC 파일 스캔
 */
export async function scanIaCFile(
    filePath: string,
    iacType: IaCType = 'unknown'
): Promise<SecurityIssue[]> {
    // Auto-detect
    if (iacType === 'unknown') {
        iacType = detectIaCType(filePath);
    }

    switch (iacType) {
        case 'dockerfile':
            return await scanDockerfile(filePath);

        case 'kubernetes':
            return await scanKubernetes(filePath);

        case 'terraform':
            return await scanTerraform(filePath);

        default:
            throw new Error(`지원하지 않는 IaC 타입: ${iacType}`);
    }
}

/**
 * IaC 스캔 결과 포맷팅
 */
export function formatIaCScanResult(
    issues: SecurityIssue[],
    iacType: IaCType
): string {
    switch (iacType) {
        case 'dockerfile':
            return formatDockerfileScanResult(issues);

        case 'kubernetes':
            return formatKubernetesScanResult(issues);

        case 'terraform':
            return formatTerraformScanResult(issues);

        default:
            return `## ⚠️ 알 수 없는 IaC 타입

${issues.length}개의 취약점이 발견되었습니다.`;
    }
}

// Re-export
export { scanDockerfile, scanKubernetes, scanTerraform };
