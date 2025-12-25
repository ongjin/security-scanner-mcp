/**
 * 파일/경로 관련 취약점 스캐너
 *
 * Path Traversal, 위험한 파일 작업, 안전하지 않은 파일 업로드 등을 검사합니다.
 * 파일 시스템 접근은 잘못하면 전체 서버가 털릴 수 있어서 중요해요!
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';

interface PathPattern {
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    fix: string;
}

const PATH_PATTERNS: PathPattern[] = [
    // Path Traversal
    {
        name: 'Path Traversal Risk',
        pattern: /(?:readFile|writeFile|unlink|rmdir|mkdir|access|stat|createReadStream|createWriteStream)\s*\(\s*(?:req\.|params\.|body\.|query\.|input)/gi,
        severity: 'critical',
        message: '사용자 입력으로 파일 경로를 구성하고 있습니다. Path Traversal 공격에 취약합니다.',
        fix: 'path.basename()으로 파일명만 추출하거나, 화이트리스트로 경로를 제한하세요',
    },
    {
        name: 'Path Traversal (Path Join)',
        pattern: /path\.join\s*\([^,]+,\s*(?:req\.|params\.|body\.|query\.)/gi,
        severity: 'high',
        message: 'path.join()에 사용자 입력을 직접 넣으면 ../ 공격에 취약합니다.',
        fix: 'path.basename()으로 정규화하거나 경로가 허용된 디렉토리 내에 있는지 검증하세요',
    },
    {
        name: 'Path Traversal Pattern',
        pattern: /\.\.[\/\\]/g,
        severity: 'medium',
        message: '../ 패턴이 코드에 있습니다. Path Traversal 관련일 수 있습니다.',
        fix: '상대 경로 대신 절대 경로를 사용하거나, 사용자 입력에서 ..를 필터링하세요',
    },

    // 위험한 파일 작업
    {
        name: 'Dangerous File Delete',
        pattern: /(?:unlink|rmdir|rm|remove).*(?:req\.|params\.|body\.|query\.)/gi,
        severity: 'critical',
        message: '사용자 입력으로 파일을 삭제하고 있습니다. 매우 위험합니다!',
        fix: '삭제할 파일 경로를 화이트리스트로 제한하세요',
    },
    {
        name: 'Recursive Delete',
        pattern: /rm\s*\(\s*[^,]+,\s*\{\s*recursive\s*:\s*true/gi,
        severity: 'high',
        message: '재귀적 삭제는 잘못 사용하면 치명적입니다.',
        fix: '삭제 전에 경로가 예상된 디렉토리 내에 있는지 확인하세요',
    },

    // 파일 업로드
    {
        name: 'Unsafe File Upload',
        pattern: /(?:originalname|filename|name)\s*(?:\.split|\.slice|\.substring)/gi,
        severity: 'medium',
        message: '업로드된 파일명을 직접 사용하면 위험합니다.',
        fix: 'UUID 등으로 파일명을 새로 생성하고, 확장자는 화이트리스트로 검증하세요',
    },
    {
        name: 'Missing File Type Validation',
        pattern: /multer|upload|formidable|busboy(?!.*mimetype|.*fileFilter)/gi,
        severity: 'medium',
        message: '파일 업로드에서 파일 타입 검증이 보이지 않습니다.',
        fix: 'mimetype과 확장자를 모두 검증하세요 (magic number 검증 권장)',
    },
    {
        name: 'Executable Upload Risk',
        pattern: /\.(exe|sh|bat|cmd|ps1|php|jsp|asp|py|rb|pl)\b.*upload/gi,
        severity: 'high',
        message: '실행 가능한 파일 확장자가 업로드 관련 코드에 있습니다.',
        fix: '실행 파일 업로드를 차단하세요',
    },

    // 임시 파일
    {
        name: 'Hardcoded Temp Path',
        pattern: /['"]\/tmp\/|['"]C:\\Temp\\/gi,
        severity: 'low',
        message: '하드코딩된 임시 경로는 이식성 문제가 있습니다.',
        fix: 'os.tmpdir()를 사용하세요',
    },
    {
        name: 'Predictable Temp Filename',
        pattern: /\/tmp\/[a-zA-Z_]+\.(txt|log|tmp)/gi,
        severity: 'medium',
        message: '예측 가능한 임시 파일명은 symlink 공격에 취약합니다.',
        fix: 'mkdtemp() 또는 랜덤 파일명을 사용하세요',
    },

    // 심볼릭 링크
    {
        name: 'Symlink Following Risk',
        pattern: /(?:readFile|createReadStream)\s*\([^)]+\)(?!.*lstat)/gi,
        severity: 'low',
        message: '심볼릭 링크를 따라가면 의도치 않은 파일에 접근할 수 있습니다.',
        fix: 'lstat()으로 심볼릭 링크인지 먼저 확인하거나, realpath()로 실제 경로 확인',
    },

    // 디렉토리 리스팅
    {
        name: 'Directory Listing',
        pattern: /(?:readdir|readdirSync)\s*\(\s*(?:req\.|params\.|body\.|query\.)/gi,
        severity: 'medium',
        message: '사용자 입력으로 디렉토리를 읽고 있습니다.',
        fix: '허용된 디렉토리 목록을 화이트리스트로 관리하세요',
    },

    // 권한 설정
    {
        name: 'Overly Permissive Mode',
        pattern: /chmod.*(?:0?777|0?666)|mode\s*:\s*(?:0?777|0?666)/gi,
        severity: 'high',
        message: '777 또는 666 권한은 너무 관대합니다.',
        fix: '필요한 최소 권한만 부여하세요 (예: 644, 755)',
    },

    // Python 관련
    {
        name: 'Python Open with User Input',
        pattern: /open\s*\(\s*(?:request\.|args\.|input\()/gi,
        severity: 'high',
        message: '사용자 입력으로 파일을 열고 있습니다.',
        fix: 'os.path.basename()으로 경로를 정규화하고, 화이트리스트 검증하세요',
    },
    {
        name: 'Python Pickle Deserialization',
        pattern: /pickle\.load|cPickle\.load|joblib\.load/gi,
        severity: 'critical',
        message: 'pickle 역직렬화는 임의 코드 실행이 가능합니다.',
        fix: '신뢰할 수 없는 데이터에는 pickle을 사용하지 마세요. JSON 등 안전한 포맷 사용.',
    },

    // Java 관련
    {
        name: 'Java Zip Slip',
        pattern: /ZipEntry.*getName\s*\(\s*\)/gi,
        severity: 'high',
        message: 'ZIP 파일 추출 시 Zip Slip 공격에 취약할 수 있습니다.',
        fix: 'entry.getName()이 "../"를 포함하는지 검증하세요',
    },
    {
        name: 'Java File with User Input',
        pattern: /new\s+File\s*\(\s*(?:request\.|params\.|input)/gi,
        severity: 'high',
        message: '사용자 입력으로 File 객체를 생성하고 있습니다.',
        fix: 'Path.normalize()로 정규화하고 경로 검증하세요',
    },
];

/**
 * 파일/경로 관련 취약점을 검사합니다.
 */
export function scanPath(code: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    for (const pattern of PATH_PATTERNS) {
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
                match: match[0].slice(0, 60),
                owaspCategory: 'A01:2021 – Broken Access Control',
                cweId: 'CWE-22',
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
