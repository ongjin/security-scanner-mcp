/**
 * 하드코딩된 시크릿 스캐너
 *
 * API 키, 비밀번호, 토큰 등이 코드에 직접 박혀있는지 검사합니다.
 * 실제로 깃허브에 시크릿 노출되는 사고가 정말 많아요...
 * 한번 노출되면 되돌리기 어려우니까 미리 잡는 게 중요!
 *
 * @author zerry
 */

import { SecurityIssue, SecretPattern, Severity } from '../types.js';

/**
 * 시크릿 패턴 정의
 *
 * 각 서비스별로 API 키 형식이 달라서 정규식으로 정의해뒀어요.
 * 참고로 이 패턴들은 gitleaks, trufflehog 등을 참고했습니다.
 */
const SECRET_PATTERNS: SecretPattern[] = [
    // AWS
    {
        name: 'AWS Access Key',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'critical',
        fix: '환경변수 AWS_ACCESS_KEY_ID 사용하거나 AWS IAM Role 사용',
    },
    {
        name: 'AWS Secret Key',
        pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        severity: 'critical',
        fix: '환경변수 AWS_SECRET_ACCESS_KEY 사용하거나 AWS IAM Role 사용',
    },

    // Google
    {
        name: 'Google API Key',
        pattern: /AIza[0-9A-Za-z-_]{35}/g,
        severity: 'high',
        fix: '환경변수로 관리하고, API 키 제한 설정하기',
    },
    {
        name: 'Google OAuth Client Secret',
        pattern: /GOCSPX-[A-Za-z0-9-_]{28}/g,
        severity: 'critical',
        fix: '환경변수로 관리하고, OAuth 설정에서 클라이언트 재생성',
    },

    // GitHub
    {
        name: 'GitHub Token',
        pattern: /ghp_[A-Za-z0-9]{36}/g,
        severity: 'critical',
        fix: '환경변수 GITHUB_TOKEN 사용, 토큰 즉시 재발급',
    },
    {
        name: 'GitHub OAuth Token',
        pattern: /gho_[A-Za-z0-9]{36}/g,
        severity: 'critical',
        fix: '환경변수로 관리, 토큰 즉시 재발급',
    },

    // Slack
    {
        name: 'Slack Token',
        pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
        severity: 'high',
        fix: '환경변수 SLACK_TOKEN 사용',
    },
    {
        name: 'Slack Webhook',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8,12}\/[a-zA-Z0-9]{24}/g,
        severity: 'high',
        fix: '환경변수로 Webhook URL 관리',
    },

    // Database 접속 정보
    {
        name: 'Database Connection String',
        pattern: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        fix: '환경변수 DATABASE_URL 사용, 비밀번호 변경 권장',
    },

    // 일반적인 패턴들
    {
        name: 'Generic API Key',
        pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9]{20,})['"]?/gi,
        severity: 'high',
        fix: '환경변수로 API 키 관리',
    },
    {
        name: 'Generic Secret',
        pattern: /(?:secret|password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]?/gi,
        severity: 'high',
        fix: '환경변수나 시크릿 매니저 사용',
    },
    {
        name: 'Private Key',
        pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        severity: 'critical',
        fix: '프라이빗 키는 절대 코드에 포함하면 안됨! 파일로 분리하고 .gitignore에 추가',
    },

    // JWT
    {
        name: 'JWT Token',
        pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*/g,
        severity: 'medium',
        fix: 'JWT 토큰은 런타임에 생성하거나 환경변수로 관리',
    },

    // 한국 서비스들
    {
        name: 'Kakao API Key',
        pattern: /(?:kakao[_-]?(?:api[_-]?)?key)\s*[=:]\s*['"]([a-f0-9]{32})['"]?/gi,
        severity: 'high',
        fix: '환경변수 KAKAO_API_KEY 사용',
    },
    {
        name: 'Naver Client Secret',
        pattern: /(?:naver[_-]?(?:client[_-]?)?secret)\s*[=:]\s*['"]([A-Za-z0-9]{10,})['"]?/gi,
        severity: 'high',
        fix: '환경변수 NAVER_CLIENT_SECRET 사용',
    },
];

/**
 * 하드코딩된 시크릿을 검사합니다.
 *
 * 각 라인을 순회하면서 시크릿 패턴이 있는지 체크해요.
 * 발견되면 심각도와 함께 이슈를 반환합니다.
 */
export function scanSecrets(code: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    // 각 패턴에 대해 검사
    for (const secretPattern of SECRET_PATTERNS) {
        // 전체 코드에서 패턴 찾기
        const matches = code.matchAll(secretPattern.pattern);

        for (const match of matches) {
            // 주석이나 예제 코드는 스킵 (false positive 줄이기)
            const matchedText = match[0];

            // 라인 번호 찾기
            let lineNumber = 1;
            let charCount = 0;
            for (let i = 0; i < lines.length; i++) {
                charCount += lines[i].length + 1; // +1 for newline
                if (charCount > (match.index || 0)) {
                    lineNumber = i + 1;
                    break;
                }
            }

            // 해당 라인이 주석인지 체크
            const line = lines[lineNumber - 1] || '';
            if (isCommentOrExample(line)) {
                continue;
            }

            // 마스킹된 매치 텍스트 (시크릿 일부 가리기)
            const maskedMatch = maskSecret(matchedText);

            issues.push({
                type: secretPattern.name,
                severity: secretPattern.severity,
                message: `${secretPattern.name}이(가) 코드에 하드코딩되어 있습니다`,
                fix: secretPattern.fix,
                line: lineNumber,
                match: maskedMatch,
                owaspCategory: 'A07:2021 – Identification and Authentication Failures',
                cweId: 'CWE-798',
            });
        }
    }

    return issues;
}

/**
 * 주석이나 예제 코드인지 판별
 *
 * false positive를 줄이기 위해서 필요해요.
 * 문서에 예제로 적어둔 건 실제 시크릿이 아니니까...
 */
function isCommentOrExample(line: string): boolean {
    const trimmed = line.trim();

    // 주석 체크
    if (trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('*') ||
        trimmed.startsWith('/*')) {
        return true;
    }

    // 예제/더미 값 체크
    const examplePatterns = [
        'example',
        'sample',
        'dummy',
        'test',
        'xxx',
        'your_',
        'your-',
        '<your',
        'placeholder',
        'changeme',
    ];

    const lowerLine = line.toLowerCase();
    return examplePatterns.some(p => lowerLine.includes(p));
}

/**
 * 시크릿 값을 마스킹
 *
 * 로그나 리포트에 전체 시크릿이 노출되면 안되니까
 * 앞뒤 일부만 보여주고 가운데는 가려요.
 */
function maskSecret(secret: string): string {
    if (secret.length <= 8) {
        return '***';
    }
    const start = secret.slice(0, 4);
    const end = secret.slice(-4);
    return `${start}****${end}`;
}
