/**
 * 인증/세션 관련 취약점 스캐너
 *
 * JWT 설정 오류, 세션 관리 문제, 인증 우회 가능성 등을 검사합니다.
 * 인증 관련 버그는 치명적인 결과를 초래할 수 있어서 꼼꼼히 봐야 해요.
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';

interface AuthPattern {
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
}

const AUTH_PATTERNS: AuthPattern[] = [
    // JWT 관련
    {
        name: 'JWT No Algorithm Verification',
        pattern: /algorithms?\s*:\s*\[\s*['"]none['"]/gi,
        severity: 'critical',
        message: 'JWT에서 "none" 알고리즘을 허용하면 서명 검증을 우회할 수 있습니다.',
        fix: 'algorithms 옵션에서 "none"을 제거하고 명시적으로 알고리즘을 지정하세요',
    },
    {
        name: 'JWT Secret in Code',
        pattern: /jwt\.sign\s*\([^,]+,\s*['"][^'"]{8,}['"]/gi,
        severity: 'critical',
        message: 'JWT 시크릿이 코드에 하드코딩되어 있습니다.',
        fix: '환경변수 process.env.JWT_SECRET을 사용하세요',
    },
    {
        name: 'JWT No Expiration',
        pattern: /jwt\.sign\s*\([^)]+\)\s*(?!.*expiresIn)/gi,
        severity: 'medium',
        message: 'JWT에 만료 시간이 설정되지 않은 것 같습니다.',
        fix: 'expiresIn 옵션을 추가하세요. 예: jwt.sign(payload, secret, { expiresIn: "1h" })',
    },
    {
        name: 'JWT Verify Without Options',
        pattern: /jwt\.verify\s*\(\s*\w+\s*,\s*\w+\s*\)(?!\s*,)/gi,
        severity: 'medium',
        message: 'JWT 검증 시 알고리즘을 명시적으로 지정하지 않았습니다.',
        fix: 'algorithms 옵션을 명시적으로 지정하세요',
    },

    // 세션 관련
    {
        name: 'Session Secret in Code',
        pattern: /session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]+['"]/gi,
        severity: 'high',
        message: '세션 시크릿이 코드에 하드코딩되어 있습니다.',
        fix: '환경변수를 사용하세요',
    },
    {
        name: 'Cookie Without HttpOnly',
        pattern: /cookie\s*\(\s*['"][^'"]+['"]\s*,\s*[^)]*(?!httpOnly)/gi,
        severity: 'medium',
        message: '쿠키에 httpOnly 플래그가 없으면 XSS로 탈취될 수 있습니다.',
        fix: 'httpOnly: true 옵션을 추가하세요',
    },
    {
        name: 'Cookie Without Secure',
        pattern: /cookie.*secure\s*:\s*false/gi,
        severity: 'medium',
        message: 'Secure 플래그가 false면 HTTP로도 쿠키가 전송됩니다.',
        fix: 'secure: true로 설정하세요 (HTTPS 환경에서)',
    },
    {
        name: 'Cookie SameSite None',
        pattern: /sameSite\s*:\s*['"]?none['"]?/gi,
        severity: 'medium',
        message: 'SameSite=None은 CSRF 공격에 취약할 수 있습니다.',
        fix: 'SameSite를 "strict" 또는 "lax"로 설정하세요',
    },

    // CORS 관련
    {
        name: 'CORS Allow All Origins',
        pattern: /(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['"]?\*['"]?/gi,
        severity: 'high',
        message: 'CORS가 모든 origin을 허용합니다. 민감한 API에서는 위험합니다.',
        fix: '허용할 origin을 명시적으로 지정하세요',
    },
    {
        name: 'CORS Credentials with Wildcard',
        pattern: /credentials\s*:\s*true.*origin\s*:\s*['"]?\*|origin\s*:\s*['"]?\*.*credentials\s*:\s*true/gi,
        severity: 'critical',
        message: 'credentials: true와 origin: "*"는 함께 사용할 수 없습니다.',
        fix: 'origin을 특정 도메인으로 지정하거나 동적으로 검증하세요',
    },

    // 비밀번호 정책
    {
        name: 'Weak Password Validation',
        pattern: /password\.length\s*[<>=]+\s*[1-6]\b/gi,
        severity: 'medium',
        message: '비밀번호 최소 길이가 너무 짧습니다.',
        fix: '최소 8자 이상을 요구하세요. 12자 이상 권장.',
    },

    // 인증 우회 가능성
    {
        name: 'Authentication Bypass Risk',
        pattern: /if\s*\(\s*(?:!user|user\s*==\s*null|!req\.user|!session)/gi,
        severity: 'low',
        message: '인증 체크 로직이 있습니다. 우회 가능성을 검토하세요.',
        fix: '모든 경로에서 인증이 올바르게 적용되는지 확인하세요',
    },

    // 하드코딩된 자격증명
    {
        name: 'Hardcoded Credentials',
        pattern: /(?:admin|root|administrator)\s*[=:]\s*['"][^'"]+['"]/gi,
        severity: 'high',
        message: '관리자 계정 정보가 하드코딩되어 있을 수 있습니다.',
        fix: '환경변수나 시크릿 매니저를 사용하세요',
    },

    // OAuth 관련
    {
        name: 'OAuth State Missing',
        pattern: /oauth.*redirect(?!.*state)/gi,
        severity: 'medium',
        message: 'OAuth에서 state 파라미터가 없으면 CSRF에 취약합니다.',
        fix: 'state 파라미터를 생성하고 검증하세요',
    },

    // 2FA 우회 위험
    {
        name: '2FA Bypass Risk',
        pattern: /(?:skip|bypass|disable).*(?:2fa|mfa|two.?factor)/gi,
        severity: 'high',
        message: '2FA 우회 로직이 있습니다. 의도된 것인지 확인하세요.',
        fix: '2FA 우회는 매우 제한된 상황에서만 허용해야 합니다',
    },
];

/**
 * 인증/세션 관련 취약점을 검사합니다.
 */
export function scanAuth(code: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    for (const pattern of AUTH_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        const matches = code.matchAll(pattern.pattern);

        for (const match of matches) {
            const lineNumber = findLineNumber(code, match.index || 0);
            const line = lines[lineNumber - 1] || '';

            if (isComment(line, language)) continue;

            issues.push({
                type: pattern.name,
                severity: pattern.severity,
                message: pattern.message,
                fix: pattern.fix,
                line: lineNumber,
                match: match[0].slice(0, 80),
                owaspCategory: 'A07:2021 – Identification and Authentication Failures',
                cweId: 'CWE-287',
            });
        }
    }

    return issues;
}

function findLineNumber(code: string, index: number): number {
    const beforeMatch = code.slice(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
}

function isComment(line: string, language: string): boolean {
    const trimmed = line.trim();
    switch (language) {
        case 'python':
            return trimmed.startsWith('#');
        default:
            return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
}
