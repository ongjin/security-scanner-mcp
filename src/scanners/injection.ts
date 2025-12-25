/**
 * SQL Injection 취약점 스캐너
 *
 * 사용자 입력이 SQL 쿼리에 직접 들어가는 위험한 패턴을 찾습니다.
 * 이거 진짜 기본 중의 기본인데, AI가 생성한 코드에서 의외로 많이 나와요.
 * Prepared Statement 쓰면 되는데 왜 안 쓰는지 모르겠음...
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';

interface InjectionPattern {
    name: string;
    pattern: RegExp;
    message: string;
    fix: string;
    languages: string[];
}

/**
 * SQL Injection 패턴 정의
 *
 * 언어별로 위험한 패턴이 조금씩 달라서 분리해뒀어요.
 */
const INJECTION_PATTERNS: InjectionPattern[] = [
    // JavaScript/TypeScript - 문자열 조합 쿼리
    {
        name: 'String Concatenation SQL',
        pattern: /(?:query|execute|sql)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:req\.|params\.|body\.|query\.)/gi,
        message: '문자열 연결로 SQL 쿼리를 만들고 있습니다. SQL Injection에 취약합니다.',
        fix: 'Prepared Statement나 Parameterized Query를 사용하세요. 예: db.query("SELECT * FROM users WHERE id = ?", [userId])',
        languages: ['javascript', 'typescript'],
    },
    {
        name: 'Template Literal SQL',
        pattern: /(?:query|execute|sql)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}/gi,
        message: '템플릿 리터럴로 SQL 쿼리에 변수를 삽입하고 있습니다. SQL Injection에 취약합니다.',
        fix: 'Prepared Statement를 사용하세요. 템플릿 리터럴 안에 직접 변수를 넣지 마세요.',
        languages: ['javascript', 'typescript'],
    },

    // Python - f-string이나 format으로 쿼리 만들기
    {
        name: 'Python f-string SQL',
        pattern: /(?:execute|cursor\.execute)\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*\{[^}]+\}/gi,
        message: 'f-string으로 SQL 쿼리를 만들고 있습니다. SQL Injection에 취약합니다.',
        fix: 'execute(sql, params) 형태로 파라미터를 분리하세요. 예: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        languages: ['python'],
    },
    {
        name: 'Python format SQL',
        pattern: /(?:execute|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\.format\s*\(/gi,
        message: '.format()으로 SQL 쿼리를 만들고 있습니다. SQL Injection에 취약합니다.',
        fix: 'Parameterized Query를 사용하세요.',
        languages: ['python'],
    },
    {
        name: 'Python % formatting SQL',
        pattern: /(?:execute|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*%s[^'"]*['"].*%/gi,
        message: '% 포맷팅으로 SQL 쿼리를 만들고 있습니다. SQL Injection에 취약합니다.',
        fix: 'execute()의 두 번째 인자로 파라미터를 전달하세요.',
        languages: ['python'],
    },

    // Java - 문자열 연결
    {
        name: 'Java String Concat SQL',
        pattern: /(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+/gi,
        message: '문자열 연결로 SQL 쿼리를 만들고 있습니다.',
        fix: 'PreparedStatement를 사용하세요. 예: PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);',
        languages: ['java'],
    },

    // 공통 - 위험한 패턴들
    {
        name: 'Raw SQL with Variable',
        pattern: /['"`](?:SELECT|INSERT|UPDATE|DELETE)\s+.+(?:WHERE|VALUES|SET)\s+.+['"`]\s*\+\s*\w+/gi,
        message: 'SQL 쿼리에 변수를 직접 연결하고 있습니다.',
        fix: 'ORM을 사용하거나 Prepared Statement를 사용하세요.',
        languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    },

    // NoSQL Injection (MongoDB 등)
    {
        name: 'MongoDB Injection',
        pattern: /(?:find|findOne|updateOne|deleteOne)\s*\(\s*\{[^}]*:\s*(?:req\.|params\.|body\.|query\.)/gi,
        message: '사용자 입력이 MongoDB 쿼리에 직접 들어가고 있습니다. NoSQL Injection에 취약합니다.',
        fix: 'mongo-sanitize 같은 라이브러리로 입력을 sanitize하거나, 스키마 검증을 추가하세요.',
        languages: ['javascript', 'typescript'],
    },

    // Command Injection
    {
        name: 'Command Injection',
        pattern: /(?:exec|spawn|execSync|spawnSync|system|popen)\s*\([^)]*(?:req\.|params\.|body\.|query\.|input)/gi,
        message: '사용자 입력이 시스템 명령어에 들어가고 있습니다. Command Injection에 취약합니다!',
        fix: '사용자 입력을 시스템 명령어에 사용하지 마세요. 꼭 필요하다면 화이트리스트 검증을 하세요.',
        languages: ['javascript', 'typescript', 'python'],
    },
];

/**
 * SQL Injection 취약점을 검사합니다.
 *
 * 언어별로 다른 패턴을 적용하고,
 * 위험한 쿼리 구성 방식을 찾아냅니다.
 */
export function scanInjection(code: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    // 해당 언어에 적용되는 패턴만 필터링
    const applicablePatterns = INJECTION_PATTERNS.filter(
        p => p.languages.includes(language) || p.languages.includes('*')
    );

    for (const pattern of applicablePatterns) {
        // 패턴 리셋 (global flag 때문에 필요)
        pattern.pattern.lastIndex = 0;

        const matches = code.matchAll(pattern.pattern);

        for (const match of matches) {
            // 라인 번호 찾기
            const lineNumber = findLineNumber(code, match.index || 0);
            const line = lines[lineNumber - 1] || '';

            // 주석은 스킵
            if (isComment(line, language)) {
                continue;
            }

            issues.push({
                type: pattern.name,
                severity: pattern.name.includes('Command') ? 'critical' : 'high',
                message: pattern.message,
                fix: pattern.fix,
                line: lineNumber,
                match: match[0].slice(0, 100), // 너무 길면 잘라내기
                owaspCategory: 'A03:2021 – Injection',
                cweId: 'CWE-89',
            });
        }
    }

    return issues;
}

/**
 * 문자 인덱스로 라인 번호 찾기
 */
function findLineNumber(code: string, index: number): number {
    const beforeMatch = code.slice(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
}

/**
 * 주석인지 체크 (언어별로 다름)
 */
function isComment(line: string, language: string): boolean {
    const trimmed = line.trim();

    switch (language) {
        case 'python':
            return trimmed.startsWith('#');
        case 'java':
        case 'javascript':
        case 'typescript':
        case 'go':
            return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
        default:
            return trimmed.startsWith('//') || trimmed.startsWith('#');
    }
}
