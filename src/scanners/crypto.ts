/**
 * 암호화 관련 취약점 스캐너
 *
 * 약한 암호화, 안전하지 않은 랜덤, 하드코딩된 IV/Salt 등을 검사합니다.
 * 암호화는 잘못 쓰면 안 쓰는 것만 못한 경우가 많아요...
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';

interface CryptoPattern {
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
}

const CRYPTO_PATTERNS: CryptoPattern[] = [
    // 약한 해시 알고리즘
    {
        name: 'Weak Hash (MD5)',
        pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
        severity: 'high',
        message: 'MD5는 충돌 공격에 취약합니다. 비밀번호 해싱에 사용하면 안됩니다.',
        fix: '비밀번호는 bcrypt/argon2, 일반 해시는 SHA-256 이상 사용',
    },
    {
        name: 'Weak Hash (SHA1)',
        pattern: /createHash\s*\(\s*['"]sha1?['"]\s*\)/gi,
        severity: 'medium',
        message: 'SHA-1은 더 이상 안전하지 않습니다.',
        fix: 'SHA-256 이상을 사용하세요',
    },

    // 안전하지 않은 랜덤
    {
        name: 'Insecure Random (Math.random)',
        pattern: /Math\.random\s*\(\s*\)/g,
        severity: 'medium',
        message: 'Math.random()은 예측 가능합니다. 보안 용도로 사용하면 안됩니다.',
        fix: 'crypto.randomBytes() 또는 crypto.randomUUID() 사용',
    },
    {
        name: 'Insecure Random (Python)',
        pattern: /\brandom\.(random|randint|choice|shuffle)\s*\(/g,
        severity: 'medium',
        message: 'random 모듈은 보안 용도로 적합하지 않습니다.',
        fix: 'secrets 모듈을 사용하세요 (secrets.token_hex(), secrets.choice() 등)',
    },

    // 하드코딩된 암호화 키/IV
    {
        name: 'Hardcoded Encryption Key',
        pattern: /(?:encryption[_-]?key|secret[_-]?key|aes[_-]?key)\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi,
        severity: 'critical',
        message: '암호화 키가 하드코딩되어 있습니다.',
        fix: '환경변수나 키 관리 서비스(AWS KMS, HashiCorp Vault)를 사용하세요',
    },
    {
        name: 'Hardcoded IV',
        pattern: /\biv\s*[=:]\s*['"][A-Fa-f0-9]{32}['"]/gi,
        severity: 'high',
        message: 'IV(Initial Vector)가 하드코딩되어 있습니다. IV는 매번 랜덤해야 합니다.',
        fix: 'crypto.randomBytes()로 매번 새로운 IV를 생성하세요',
    },
    {
        name: 'Hardcoded Salt',
        pattern: /\bsalt\s*[=:]\s*['"][A-Za-z0-9+/=]{8,}['"]/gi,
        severity: 'high',
        message: 'Salt가 하드코딩되어 있습니다. Salt는 사용자마다 달라야 합니다.',
        fix: '각 사용자에 대해 랜덤 salt를 생성하고 해시와 함께 저장하세요',
    },

    // ECB 모드 사용
    {
        name: 'ECB Mode Encryption',
        pattern: /(?:aes|des)[_-]?(?:128|192|256)?[_-]?ecb/gi,
        severity: 'high',
        message: 'ECB 모드는 패턴이 노출되어 안전하지 않습니다.',
        fix: 'CBC, GCM, CTR 등 더 안전한 모드를 사용하세요 (GCM 권장)',
    },
    {
        name: 'DES Encryption',
        pattern: /(?:createCipher|createDecipher)\s*\(\s*['"]des(?:-ede3)?['"]/gi,
        severity: 'high',
        message: 'DES는 더 이상 안전하지 않습니다.',
        fix: 'AES-256-GCM을 사용하세요',
    },

    // 불안전한 TLS/SSL 설정
    {
        name: 'Disabled SSL Verification',
        pattern: /rejectUnauthorized\s*:\s*false|verify\s*[=:]\s*false|CERT_NONE/gi,
        severity: 'critical',
        message: 'SSL 인증서 검증이 비활성화되어 있습니다. MITM 공격에 취약합니다.',
        fix: 'SSL 인증서 검증을 활성화하세요. 개발 환경에서만 비활성화하고 프로덕션에서는 절대 사용하지 마세요.',
    },
    {
        name: 'Insecure TLS Version',
        pattern: /(?:TLSv1|SSLv3|TLS_v1_0|TLS_v1_1)(?!_2|_3)/gi,
        severity: 'high',
        message: 'TLS 1.0/1.1 또는 SSL은 더 이상 안전하지 않습니다.',
        fix: 'TLS 1.2 이상을 사용하세요',
    },

    // 비밀번호 평문 저장
    {
        name: 'Plain Password Storage',
        pattern: /password\s*[=:]\s*(?:req\.body|request\.|params\.|input)/gi,
        severity: 'high',
        message: '비밀번호를 해싱 없이 저장하려는 것 같습니다.',
        fix: 'bcrypt.hash()로 비밀번호를 해싱한 후 저장하세요',
    },

    // 비밀번호 비교 취약점
    {
        name: 'Timing Attack Vulnerable Comparison',
        pattern: /password\s*===?\s*(?:stored|db|user)\./gi,
        severity: 'medium',
        message: '문자열 비교는 timing attack에 취약할 수 있습니다.',
        fix: 'crypto.timingSafeEqual() 또는 bcrypt.compare()를 사용하세요',
    },
];

/**
 * 암호화 관련 취약점을 검사합니다.
 */
export function scanCrypto(code: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    for (const pattern of CRYPTO_PATTERNS) {
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
                match: match[0],
                owaspCategory: 'A02:2021 – Cryptographic Failures',
                cweId: 'CWE-327',
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
