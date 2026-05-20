/**
 * Cryptographic-misuse scanner.
 * The Plain Password Storage pattern uses Pass-2 taint extension (#3).
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
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  fix: string;
}
interface TaintAwarePattern {
  name: string;
  prefix: string;
  staticSinks: string[];
  suffix?: string;
  flags?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  fix: string;
  languages: Language[];
}

const STATIC_PATTERNS: StaticPattern[] = [
  { name: 'Weak Hash (MD5)',            pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,                                                 severity: 'high',     message: 'MD5는 충돌 공격에 취약합니다.',                       fix: 'SHA-256 이상' },
  { name: 'Weak Hash (SHA1)',           pattern: /createHash\s*\(\s*['"]sha1?['"]\s*\)/gi,                                              severity: 'medium',   message: 'SHA-1은 안전하지 않습니다.',                          fix: 'SHA-256 이상' },
  { name: 'Insecure Random (Math.random)', pattern: /Math\.random\s*\(\s*\)/g,                                                          severity: 'medium',   message: 'Math.random()은 예측 가능합니다.',                    fix: 'crypto.randomBytes()' },
  { name: 'Insecure Random (Python)',   pattern: /\brandom\.(random|randint|choice|shuffle)\s*\(/g,                                     severity: 'medium',   message: 'random 모듈은 보안 용도에 부적합합니다.',              fix: 'secrets 모듈' },
  { name: 'Hardcoded Encryption Key',   pattern: /(?:encryption[_-]?key|secret[_-]?key|aes[_-]?key)\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi, severity: 'critical', message: '암호화 키가 하드코딩되어 있습니다.',                fix: 'KMS / 환경변수' },
  { name: 'Hardcoded IV',               pattern: /\biv\s*[=:]\s*['"][A-Fa-f0-9]{32}['"]/gi,                                             severity: 'high',     message: 'IV가 하드코딩되어 있습니다.',                          fix: 'crypto.randomBytes()' },
  { name: 'Hardcoded Salt',             pattern: /\bsalt\s*[=:]\s*['"][A-Za-z0-9+/=]{8,}['"]/gi,                                        severity: 'high',     message: 'Salt가 하드코딩되어 있습니다.',                        fix: '사용자별 랜덤 salt' },
  { name: 'ECB Mode Encryption',        pattern: /(?:aes|des)[_-]?(?:128|192|256)?[_-]?ecb/gi,                                          severity: 'high',     message: 'ECB 모드는 패턴이 노출됩니다.',                       fix: 'GCM 등 사용' },
  { name: 'DES Encryption',             pattern: /(?:createCipher|createDecipher)\s*\(\s*['"]des(?:-ede3)?['"]/gi,                       severity: 'high',     message: 'DES는 안전하지 않습니다.',                            fix: 'AES-256-GCM' },
  { name: 'Disabled SSL Verification',  pattern: /rejectUnauthorized\s*:\s*false|verify\s*[=:]\s*false|CERT_NONE/gi,                    severity: 'critical', message: 'SSL 검증이 비활성화되어 있습니다.',                    fix: 'SSL 검증 활성화' },
  { name: 'Insecure TLS Version',       pattern: /(?:TLSv1|SSLv3|TLS_v1_0|TLS_v1_1)(?!_2|_3)/gi,                                        severity: 'high',     message: 'TLS 1.0/1.1은 안전하지 않습니다.',                    fix: 'TLS 1.2 이상' },
  { name: 'Timing Attack Vulnerable Comparison', pattern: /password\s*===?\s*(?:stored|db|user)\./gi,                                   severity: 'medium',   message: '문자열 비교는 timing attack에 취약할 수 있습니다.',    fix: 'crypto.timingSafeEqual()' },
];

const TAINT_AWARE_PATTERNS: TaintAwarePattern[] = [
  {
    name: 'Plain Password Storage',
    prefix: `password\\s*[=:]\\s*`,
    staticSinks: ['req\\.body', 'request\\.', 'params\\.', 'input'],
    severity: 'high',
    message: '비밀번호를 해싱 없이 저장하려는 것 같습니다.',
    fix: 'bcrypt.hash()로 해싱',
    languages: ['javascript', 'typescript', 'python'],
  },
];

export function scanCrypto(code: string, language: string): SecurityIssue[] {
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
        line: lineNumber, match: match[0],
        owaspCategory: 'A02:2021 – Cryptographic Failures', cweId: 'CWE-327',
      });
    }
  }
  return issues;
}
