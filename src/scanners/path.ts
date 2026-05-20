/**
 * File/path-related vulnerability scanner.
 * 6 patterns use Pass-2 taint extension (#3).
 */

import { SecurityIssue } from '../types.js';
import {
  lineOf,
  isCommentLine,
  isInBlockComment,
  collectTaintedVars,
  taintAlternation,
  Language,
} from '../utils/source-helpers.js';

interface StaticPattern {
  name: string; pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string; fix: string;
}
interface TaintAwarePattern {
  name: string; prefix: string; staticSinks: string[]; suffix?: string; flags?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string; fix: string; languages: Language[];
}

const STATIC_PATTERNS: StaticPattern[] = [
  { name: 'Path Traversal Pattern',         pattern: /\.\.[/\\]/g,                                                 severity: 'medium',   message: '../ 패턴이 코드에 있습니다.',         fix: '절대 경로 또는 입력 검증' },
  { name: 'Recursive Delete',               pattern: /rm\s*\(\s*[^,]+,\s*\{\s*recursive\s*:\s*true/gi,             severity: 'high',     message: '재귀적 삭제는 위험합니다.',           fix: '경로 화이트리스트' },
  { name: 'Unsafe File Upload',             pattern: /(?:originalname|filename|name)\s*(?:\.split|\.slice|\.substring)/gi, severity: 'medium', message: '업로드 파일명을 직접 사용합니다.', fix: 'UUID 사용' },
  { name: 'Missing File Type Validation',   pattern: /multer|upload|formidable|busboy(?!.*mimetype|.*fileFilter)/gi, severity: 'medium',  message: '파일 타입 검증이 없습니다.',          fix: 'mimetype 검증' },
  { name: 'Executable Upload Risk',         pattern: /\.(exe|sh|bat|cmd|ps1|php|jsp|asp|py|rb|pl)\b.*upload/gi,     severity: 'high',     message: '실행 파일 업로드.',                    fix: '확장자 차단' },
  { name: 'Hardcoded Temp Path',            pattern: /['"]\/tmp\/|['"]C:\\Temp\\/gi,                                severity: 'low',      message: '하드코딩된 임시 경로.',                fix: 'os.tmpdir()' },
  { name: 'Predictable Temp Filename',      pattern: /\/tmp\/[a-zA-Z_]+\.(txt|log|tmp)/gi,                          severity: 'medium',   message: '예측 가능한 임시 파일명.',             fix: 'mkdtemp()' },
  { name: 'Symlink Following Risk',         pattern: /(?:readFile|createReadStream)\s*\([^)]+\)(?!.*lstat)/gi,     severity: 'low',      message: 'symlink 위험.',                        fix: 'lstat() 확인' },
  { name: 'Overly Permissive Mode',         pattern: /chmod.*(?:0?o?777|0?o?666)|mode\s*:\s*(?:0?o?777|0?o?666)/gi, severity: 'high',    message: '777/666 권한은 위험합니다.',           fix: '최소 권한' },
  { name: 'Python Pickle Deserialization',  pattern: /pickle\.load|cPickle\.load|joblib\.load/gi,                  severity: 'critical', message: 'pickle 역직렬화는 RCE 가능.',          fix: 'JSON 사용' },
  { name: 'Java Zip Slip',                  pattern: /ZipEntry.*getName\s*\(\s*\)/gi,                              severity: 'high',     message: 'Zip Slip 가능.',                        fix: 'entry.getName() 검증' },
];

const TAINT_AWARE_PATTERNS: TaintAwarePattern[] = [
  { name: 'Path Traversal Risk',          prefix: `(?:readFile|writeFile|unlink|rmdir|mkdir|access|stat|createReadStream|createWriteStream)\\s*\\(\\s*`, staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.', 'input'], severity: 'critical', message: '사용자 입력으로 파일 경로 구성. Path Traversal.', fix: 'path.basename() 또는 화이트리스트',         languages: ['javascript', 'typescript'] },
  { name: 'Path Traversal (Path Join)',   prefix: `path\\.join\\s*\\([^,]+,\\s*`,                                                                          staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.'],          severity: 'high',     message: 'path.join()에 사용자 입력.',             fix: 'path.basename() 정규화',                      languages: ['javascript', 'typescript'] },
  { name: 'Dangerous File Delete',        prefix: `(?:unlink|rmdir|rm|remove)[^(]*\\([^)]*`,                                                              staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.'],          severity: 'critical', message: '사용자 입력으로 파일 삭제!',              fix: '경로 화이트리스트',                            languages: ['javascript', 'typescript'] },
  { name: 'Directory Listing',            prefix: `(?:readdir|readdirSync)\\s*\\(\\s*`,                                                                    staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.'],          severity: 'medium',   message: '사용자 입력으로 디렉토리 읽기.',           fix: '허용 디렉토리 화이트리스트',                   languages: ['javascript', 'typescript'] },
  { name: 'Python Open with User Input',  prefix: `open\\s*\\(\\s*`,                                                                                       staticSinks: ['request\\.', 'args\\.', 'input\\('],                   severity: 'high',     message: '사용자 입력으로 파일 열기.',               fix: 'os.path.basename() 정규화',                    languages: ['python'] },
  { name: 'Java File with User Input',    prefix: `new\\s+File\\s*\\(\\s*`,                                                                                staticSinks: ['request\\.', 'params\\.', 'input'],                    severity: 'high',     message: '사용자 입력으로 File 객체 생성.',         fix: 'Path.normalize()',                             languages: ['java'] },
];

export function scanPath(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  const issues: SecurityIssue[] = [];
  const lines = code.split('\n');
  const tainted = collectTaintedVars(code, lang);

  type Compiled = { name: string; regex: RegExp; severity: 'critical' | 'high' | 'medium' | 'low'; message: string; fix: string };
  const compiled: Compiled[] = STATIC_PATTERNS.map(p => ({
    name: p.name, regex: p.pattern, severity: p.severity, message: p.message, fix: p.fix,
  }));

  for (const p of TAINT_AWARE_PATTERNS) {
    if (!p.languages.includes(lang)) continue;
    const sinks = p.staticSinks.join('|') + taintAlternation(tainted);
    compiled.push({
      name: p.name,
      regex: new RegExp(`${p.prefix}(?:${sinks})${p.suffix ?? ''}`, p.flags ?? 'gi'),
      severity: p.severity, message: p.message, fix: p.fix,
    });
  }

  for (const p of compiled) {
    p.regex.lastIndex = 0;
    const matches = code.matchAll(p.regex);
    for (const match of matches) {
      const matchIndex = match.index ?? 0;
      const lineNumber = lineOf(code, matchIndex);
      const line = lines[lineNumber - 1] ?? '';
      if (isCommentLine(line, lang)) continue;
      if (isInBlockComment(code, matchIndex)) continue;

      issues.push({
        type: p.name, severity: p.severity, message: p.message, fix: p.fix,
        line: lineNumber, match: match[0].slice(0, 60),
        owaspCategory: 'A01:2021 – Broken Access Control', cweId: 'CWE-22',
      });
    }
  }
  return issues;
}
