/**
 * 보안 스캐너 타입 정의
 *
 * @author zerry
 */

/**
 * 취약점 심각도
 * OWASP 기준으로 분류했어요
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * 보안 이슈 타입
 *
 * 발견된 각 취약점을 표현합니다.
 * line이 undefined인 경우는 정확한 위치를 특정하기 어려운 경우예요.
 */
export interface SecurityIssue {
    /** 취약점 종류 (예: "Hardcoded API Key", "SQL Injection") */
    type: string;

    /** 심각도 */
    severity: Severity;

    /** 사람이 읽을 수 있는 설명 */
    message: string;

    /** 해결 방법 제안 */
    fix: string;

    /** 발견된 라인 번호 (1-indexed) */
    line?: number;

    /** 매칭된 원본 텍스트 (시크릿의 경우 마스킹 필요) */
    match?: string;

    /** OWASP 카테고리 (있으면) */
    owaspCategory?: string;

    /** CWE ID (있으면) */
    cweId?: string;

    /** 추가 메타데이터 (IaC 규칙 ID, CVE 정보 등) */
    metadata?: Record<string, any>;
}

/**
 * 스캔 결과
 */
export interface ScanResult {
    /** 스캔 성공 여부 */
    success: boolean;

    /** 발견된 이슈들 */
    issues: SecurityIssue[];

    /** 스캔에 걸린 시간 (ms) */
    duration?: number;

    /** 검사한 라인 수 */
    linesScanned?: number;
}

/**
 * 시크릿 패턴 정의
 *
 * 각 서비스별로 API 키 패턴이 달라서
 * 정규식으로 정의해뒀어요
 */
export interface SecretPattern {
    /** 패턴 이름 */
    name: string;

    /** 정규식 */
    pattern: RegExp;

    /** 심각도 */
    severity: Severity;

    /** 해결책 */
    fix: string;
}
