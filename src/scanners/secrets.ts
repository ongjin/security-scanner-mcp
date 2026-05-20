/**
 * Hardcoded-secret scanner.
 * Placeholder values (e.g. "your_api_key_here") are filtered out at the
 * matched-value level, not by surrounding line text.
 */

import { SecurityIssue, SecretPattern } from '../types.js';
import {
  lineOf,
  isCommentLine,
  isInBlockComment,
  stripInlineComments,
  isPlaceholderValue,
  Language,
} from '../utils/source-helpers.js';

const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key',                pattern: /AKIA[0-9A-Z]{16}/g,                                                                                  severity: 'critical', fix: '환경변수 AWS_ACCESS_KEY_ID 사용하거나 AWS IAM Role 사용' },
  { name: 'AWS Secret Key',                pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical', fix: '환경변수 AWS_SECRET_ACCESS_KEY 사용하거나 AWS IAM Role 사용' },
  { name: 'Google API Key',                pattern: /AIza[0-9A-Za-z-_]{35}/g,                                                                              severity: 'high',     fix: '환경변수로 관리하고, API 키 제한 설정하기' },
  { name: 'Google OAuth Client Secret',    pattern: /GOCSPX-[A-Za-z0-9-_]{28}/g,                                                                            severity: 'critical', fix: '환경변수로 관리하고, OAuth 설정에서 클라이언트 재생성' },
  { name: 'GitHub Token',                  pattern: /ghp_[A-Za-z0-9]{36}/g,                                                                                 severity: 'critical', fix: '환경변수 GITHUB_TOKEN 사용, 토큰 즉시 재발급' },
  { name: 'GitHub OAuth Token',            pattern: /gho_[A-Za-z0-9]{36}/g,                                                                                 severity: 'critical', fix: '환경변수로 관리, 토큰 즉시 재발급' },
  { name: 'Slack Token',                   pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,                                                   severity: 'high',     fix: '환경변수 SLACK_TOKEN 사용' },
  { name: 'Slack Webhook',                 pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8,12}\/[a-zA-Z0-9]{24}/g,               severity: 'high',     fix: '환경변수로 Webhook URL 관리' },
  { name: 'Database Connection String',    pattern: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^:]+:[^@]+@[^/]+/gi,                                    severity: 'critical', fix: '환경변수 DATABASE_URL 사용, 비밀번호 변경 권장' },
  { name: 'Generic API Key',               pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9]{20,})['"]?/gi,                                       severity: 'high',     fix: '환경변수로 API 키 관리' },
  { name: 'Generic Secret',                pattern: /(?:secret|password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]?/gi,                                      severity: 'high',     fix: '환경변수나 시크릿 매니저 사용' },
  { name: 'Private Key',                   pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,                                              severity: 'critical', fix: '프라이빗 키는 절대 코드에 포함하면 안됨!' },
  { name: 'JWT Token',                     pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*/g,                                               severity: 'medium',   fix: 'JWT 토큰은 런타임에 생성하거나 환경변수로 관리' },
  { name: 'Kakao API Key',                 pattern: /(?:kakao[_-]?(?:api[_-]?)?key)\s*[=:]\s*['"]([a-f0-9]{32})['"]?/gi,                                   severity: 'high',     fix: '환경변수 KAKAO_API_KEY 사용' },
  { name: 'Naver Client Secret',           pattern: /(?:naver[_-]?(?:client[_-]?)?secret)\s*[=:]\s*['"]([A-Za-z0-9]{10,})['"]?/gi,                          severity: 'high',     fix: '환경변수 NAVER_CLIENT_SECRET 사용' },
];

export function scanSecrets(code: string, language: Language = 'javascript'): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const lines = code.split('\n');

  for (const secretPattern of SECRET_PATTERNS) {
    secretPattern.pattern.lastIndex = 0;
    const matches = code.matchAll(secretPattern.pattern);

    for (const match of matches) {
      const matchIndex = match.index ?? 0;
      const lineNumber = lineOf(code, matchIndex);
      const line = lines[lineNumber - 1] ?? '';

      if (isCommentLine(line, language)) continue;
      if (isInBlockComment(code, matchIndex)) continue;

      // Inline-comment tail check.
      const lastNl = code.lastIndexOf('\n', matchIndex - 1);
      const columnInLine = lastNl === -1 ? matchIndex : matchIndex - lastNl - 1;
      const live = stripInlineComments(line, language);
      if (columnInLine >= live.length) continue;

      const matchedValue = match[1] ?? match[0];
      if (isPlaceholderValue(matchedValue)) continue;

      issues.push({
        type: secretPattern.name,
        severity: secretPattern.severity,
        message: `${secretPattern.name}이(가) 코드에 하드코딩되어 있습니다`,
        fix: secretPattern.fix,
        line: lineNumber,
        match: maskSecret(matchedValue),
        owaspCategory: 'A07:2021 – Identification and Authentication Failures',
        cweId: 'CWE-798',
      });
    }
  }

  return issues;
}

function maskSecret(secret: string): string {
  if (secret.length <= 8) return '***';
  return `${secret.slice(0, 4)}****${secret.slice(-4)}`;
}
