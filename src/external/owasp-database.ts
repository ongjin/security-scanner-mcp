/**
 * OWASP 정보 데이터베이스
 *
 * OWASP Top 10 및 CWE 정보를 제공합니다.
 * 외부 API 호출 없이 로컬 데이터로 빠르게 조회 가능합니다.
 *
 * @author zerry
 */

/**
 * OWASP 카테고리 정보
 */
export interface OWASPCategory {
    id: string;
    name: string;
    description: string;
    examples: string[];
    mitigations: string[];
    references: string[];
}

/**
 * CWE 정보
 */
export interface CWEInfo {
    id: string;
    name: string;
    description: string;
    owaspMapping?: string[]; // 매핑되는 OWASP 카테고리
    severity: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * OWASP Top 10:2021 데이터베이스
 */
export const OWASP_TOP_10_2021: Record<string, OWASPCategory> = {
    'A01:2021': {
        id: 'A01:2021',
        name: 'Broken Access Control',
        description: '권한 없는 사용자가 제한된 리소스에 접근하거나 작업을 수행할 수 있는 취약점',
        examples: [
            'URL 조작으로 타 사용자 데이터 접근',
            'API 권한 검증 누락',
            'CORS 잘못된 설정',
            'JWT 검증 우회'
        ],
        mitigations: [
            '최소 권한 원칙 적용',
            '모든 요청에 대해 서버 측 권한 검증',
            'Access Control 정책 중앙 집중화',
            '세션 무효화 적절히 수행'
        ],
        references: [
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        ]
    },
    'A02:2021': {
        id: 'A02:2021',
        name: 'Cryptographic Failures',
        description: '암호화 관련 실패로 인한 민감 데이터 노출',
        examples: [
            '평문 전송 (HTTP)',
            '약한 암호화 알고리즘 (MD5, SHA1)',
            '하드코딩된 암호화 키',
            '취약한 TLS 설정'
        ],
        mitigations: [
            'HTTPS 강제 사용',
            '강력한 암호화 알고리즘 (AES-256, SHA-256 이상)',
            '암호화 키 별도 관리 (Key Management Service)',
            'TLS 1.2 이상 사용'
        ],
        references: [
            'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
        ]
    },
    'A03:2021': {
        id: 'A03:2021',
        name: 'Injection',
        description: '신뢰할 수 없는 데이터가 명령어나 쿼리의 일부로 실행되는 취약점',
        examples: [
            'SQL Injection',
            'NoSQL Injection',
            'OS Command Injection',
            'LDAP Injection',
            'XPath/XML Injection'
        ],
        mitigations: [
            'Parameterized Query 사용',
            'ORM 프레임워크 활용',
            '입력 검증 및 이스케이핑',
            '최소 권한 DB 계정 사용'
        ],
        references: [
            'https://owasp.org/Top10/A03_2021-Injection/'
        ]
    },
    'A04:2021': {
        id: 'A04:2021',
        name: 'Insecure Design',
        description: '설계 단계에서의 보안 결함',
        examples: [
            '비즈니스 로직 결함',
            '인증/권한 설계 오류',
            '부적절한 에러 처리 설계'
        ],
        mitigations: [
            'Threat Modeling 수행',
            'Secure Development Lifecycle 적용',
            'Security Architecture Review'
        ],
        references: [
            'https://owasp.org/Top10/A04_2021-Insecure_Design/'
        ]
    },
    'A05:2021': {
        id: 'A05:2021',
        name: 'Security Misconfiguration',
        description: '부적절한 보안 설정으로 인한 취약점',
        examples: [
            'Default 계정/비밀번호 사용',
            '불필요한 서비스 활성화',
            '에러 메시지에 민감 정보 노출',
            '보안 헤더 누락'
        ],
        mitigations: [
            '보안 강화 가이드 적용',
            '불필요한 기능 비활성화',
            '자동화된 보안 설정 검증',
            '정기적인 보안 패치'
        ],
        references: [
            'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        ]
    },
    'A06:2021': {
        id: 'A06:2021',
        name: 'Vulnerable and Outdated Components',
        description: '알려진 취약점이 있는 라이브러리 및 컴포넌트 사용',
        examples: [
            '오래된 npm 패키지',
            'CVE가 있는 라이브러리',
            'EOL 소프트웨어 사용'
        ],
        mitigations: [
            '정기적인 의존성 업데이트',
            'npm audit, Snyk 등 취약점 스캔',
            '사용하지 않는 의존성 제거',
            'SCA (Software Composition Analysis) 도구 활용'
        ],
        references: [
            'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
        ]
    },
    'A07:2021': {
        id: 'A07:2021',
        name: 'Identification and Authentication Failures',
        description: '인증 및 세션 관리 취약점',
        examples: [
            '약한 비밀번호 정책',
            'Credential Stuffing 공격 가능',
            '세션 ID 노출',
            'Multi-factor authentication 미적용'
        ],
        mitigations: [
            '강력한 비밀번호 정책',
            'MFA 적용',
            '세션 관리 프레임워크 사용',
            'Rate limiting 및 계정 잠금 정책'
        ],
        references: [
            'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
        ]
    },
    'A08:2021': {
        id: 'A08:2021',
        name: 'Software and Data Integrity Failures',
        description: '소프트웨어 및 데이터 무결성 검증 실패',
        examples: [
            'CI/CD 파이프라인 변조',
            '검증되지 않은 업데이트',
            '역직렬화 취약점',
            '서명되지 않은 패키지 사용'
        ],
        mitigations: [
            '디지털 서명 검증',
            'Integrity check (checksum, hash)',
            '신뢰할 수 있는 소스에서만 다운로드',
            '역직렬화 시 타입 검증'
        ],
        references: [
            'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
        ]
    },
    'A09:2021': {
        id: 'A09:2021',
        name: 'Security Logging and Monitoring Failures',
        description: '보안 로깅 및 모니터링 부족',
        examples: [
            '로그인 실패 미기록',
            '보안 이벤트 감지 누락',
            '로그 보관 기간 부족',
            '로그 무결성 검증 미흡'
        ],
        mitigations: [
            '중요 이벤트 로깅',
            'SIEM 도구 활용',
            '실시간 알람 설정',
            '로그 무결성 보호'
        ],
        references: [
            'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
        ]
    },
    'A10:2021': {
        id: 'A10:2021',
        name: 'Server-Side Request Forgery (SSRF)',
        description: '서버가 악의적인 요청을 외부 리소스로 전송하도록 유도하는 공격',
        examples: [
            '내부 네트워크 스캔',
            '클라우드 메타데이터 접근 (AWS IMDS)',
            '방화벽 우회'
        ],
        mitigations: [
            'URL 허용 목록 사용',
            '내부 IP 대역 차단',
            '네트워크 세그멘테이션',
            '응답 검증'
        ],
        references: [
            'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
        ]
    }
};

/**
 * CWE 데이터베이스 (주요 CWE만 포함)
 */
export const CWE_DATABASE: Record<string, CWEInfo> = {
    'CWE-20': {
        id: 'CWE-20',
        name: 'Improper Input Validation',
        description: '입력 검증이 부적절하거나 누락되어 발생하는 취약점',
        owaspMapping: ['A03:2021'],
        severity: 'high'
    },
    'CWE-79': {
        id: 'CWE-79',
        name: 'Cross-site Scripting (XSS)',
        description: '신뢰할 수 없는 데이터가 웹 페이지에 포함되어 사용자 브라우저에서 실행되는 취약점',
        owaspMapping: ['A03:2021'],
        severity: 'high'
    },
    'CWE-89': {
        id: 'CWE-89',
        name: 'SQL Injection',
        description: 'SQL 쿼리에 악의적인 입력이 삽입되어 실행되는 취약점',
        owaspMapping: ['A03:2021'],
        severity: 'critical'
    },
    'CWE-200': {
        id: 'CWE-200',
        name: 'Exposure of Sensitive Information',
        description: '민감한 정보가 권한 없는 사용자에게 노출되는 취약점',
        owaspMapping: ['A01:2021', 'A02:2021'],
        severity: 'medium'
    },
    'CWE-250': {
        id: 'CWE-250',
        name: 'Execution with Unnecessary Privileges',
        description: '불필요하게 높은 권한으로 실행되는 취약점',
        owaspMapping: ['A01:2021', 'A05:2021'],
        severity: 'high'
    },
    'CWE-287': {
        id: 'CWE-287',
        name: 'Improper Authentication',
        description: '인증이 부적절하거나 우회 가능한 취약점',
        owaspMapping: ['A07:2021'],
        severity: 'critical'
    },
    'CWE-295': {
        id: 'CWE-295',
        name: 'Improper Certificate Validation',
        description: 'TLS/SSL 인증서 검증이 부적절한 취약점',
        owaspMapping: ['A02:2021'],
        severity: 'high'
    },
    'CWE-312': {
        id: 'CWE-312',
        name: 'Cleartext Storage of Sensitive Information',
        description: '민감한 정보가 평문으로 저장되는 취약점',
        owaspMapping: ['A02:2021'],
        severity: 'high'
    },
    'CWE-326': {
        id: 'CWE-326',
        name: 'Inadequate Encryption Strength',
        description: '취약한 암호화 알고리즘 사용',
        owaspMapping: ['A02:2021'],
        severity: 'high'
    },
    'CWE-327': {
        id: 'CWE-327',
        name: 'Use of a Broken or Risky Cryptographic Algorithm',
        description: '안전하지 않은 암호화 알고리즘 사용 (MD5, SHA1 등)',
        owaspMapping: ['A02:2021'],
        severity: 'high'
    },
    'CWE-502': {
        id: 'CWE-502',
        name: 'Deserialization of Untrusted Data',
        description: '신뢰할 수 없는 데이터의 역직렬화로 인한 취약점',
        owaspMapping: ['A08:2021'],
        severity: 'critical'
    },
    'CWE-732': {
        id: 'CWE-732',
        name: 'Incorrect Permission Assignment',
        description: '부적절한 권한 설정',
        owaspMapping: ['A01:2021', 'A05:2021'],
        severity: 'medium'
    },
    'CWE-798': {
        id: 'CWE-798',
        name: 'Use of Hard-coded Credentials',
        description: '하드코딩된 자격증명 사용',
        owaspMapping: ['A02:2021', 'A07:2021'],
        severity: 'critical'
    },
    'CWE-918': {
        id: 'CWE-918',
        name: 'Server-Side Request Forgery (SSRF)',
        description: '서버가 악의적인 요청을 전송하도록 유도하는 공격',
        owaspMapping: ['A10:2021'],
        severity: 'high'
    },
    'CWE-1004': {
        id: 'CWE-1004',
        name: 'Sensitive Cookie Without HttpOnly Flag',
        description: 'HttpOnly 플래그가 없는 민감한 쿠키',
        owaspMapping: ['A05:2021'],
        severity: 'medium'
    }
};

/**
 * OWASP 카테고리 조회
 */
export function getOWASPInfo(categoryId: string): OWASPCategory | null {
    return OWASP_TOP_10_2021[categoryId] || null;
}

/**
 * CWE 정보 조회
 */
export function getCWEInfo(cweId: string): CWEInfo | null {
    return CWE_DATABASE[cweId] || null;
}

/**
 * CWE에서 OWASP 매핑 조회
 */
export function getOWASPFromCWE(cweId: string): string[] {
    const cwe = getCWEInfo(cweId);
    return cwe?.owaspMapping || [];
}

/**
 * 모든 OWASP 카테고리 목록
 */
export function getAllOWASPCategories(): OWASPCategory[] {
    return Object.values(OWASP_TOP_10_2021);
}

/**
 * 심각도별 CWE 목록
 */
export function getCWEsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): CWEInfo[] {
    return Object.values(CWE_DATABASE).filter(cwe => cwe.severity === severity);
}
