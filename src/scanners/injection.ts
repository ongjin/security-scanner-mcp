/**
 * SQL / NoSQL / Command injection scanner.
 * Implements one-hop taint tracking via Pass 1 (collectTaintedVars) and
 * Pass 2 (extending sink alternations in select patterns).
 */

import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode,
  walk,
  analyzeTaint,
  isTainted,
  matchSink,
  SQL_SINKS,
  COMMAND_SINKS,
  MONGO_SINKS,
  toIssue,
  type ParseResult,
  type SinkDefinition,
  type SinkMatchResult,
} from '../utils/ast/index.js';
import {
  lineOf,
  isCommentLine,
  isInBlockComment,
  collectTaintedVars,
  taintAlternation,
  type Language,
} from '../utils/source-helpers.js';

interface StaticPattern {
  name: string;
  pattern: RegExp;
  message: string;
  fix: string;
  languages: Language[];
  severity?: 'critical' | 'high';
}

interface TaintAwarePattern {
  name: string;
  prefix: string;
  staticSinks: string[];
  suffix?: string;
  flags?: string;
  message: string;
  fix: string;
  languages: Language[];
  severity?: 'critical' | 'high';
}

const STATIC_PATTERNS: StaticPattern[] = [
  {
    name: 'Template Literal SQL',
    pattern: /(?:query|execute|sql)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}/gi,
    message: '템플릿 리터럴로 SQL 쿼리에 변수를 삽입하고 있습니다. SQL Injection에 취약합니다.',
    fix: 'Prepared Statement를 사용하세요.',
    languages: ['javascript', 'typescript'],
    severity: 'high',
  },
  {
    name: 'Python f-string SQL',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*\{[^}]+\}/gi,
    message: 'f-string으로 SQL 쿼리를 만들고 있습니다.',
    fix: 'execute(sql, params) 형태로 파라미터를 분리하세요.',
    languages: ['python'],
    severity: 'high',
  },
  {
    name: 'Python format SQL',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\.format\s*\(/gi,
    message: '.format()으로 SQL 쿼리를 만들고 있습니다.',
    fix: 'Parameterized Query를 사용하세요.',
    languages: ['python'],
    severity: 'high',
  },
  {
    name: 'Python % formatting SQL',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*%s[^'"]*['"].*%/gi,
    message: '% 포맷팅으로 SQL 쿼리를 만들고 있습니다.',
    fix: 'execute()의 두 번째 인자로 파라미터를 전달하세요.',
    languages: ['python'],
    severity: 'high',
  },
  {
    name: 'Java String Concat SQL',
    pattern: /(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+/gi,
    message: '문자열 연결로 SQL 쿼리를 만들고 있습니다.',
    fix: 'PreparedStatement를 사용하세요.',
    languages: ['java'],
    severity: 'high',
  },
  {
    name: 'Raw SQL with Variable',
    pattern: /['"`](?:SELECT|INSERT|UPDATE|DELETE)\s+.+(?:WHERE|VALUES|SET)\s+.+['"`]\s*\+\s*\w+/gi,
    message: 'SQL 쿼리에 변수를 직접 연결하고 있습니다.',
    fix: 'ORM 또는 Prepared Statement를 사용하세요.',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    severity: 'high',
  },
];

const TAINT_AWARE_PATTERNS: TaintAwarePattern[] = [
  {
    name: 'String Concatenation SQL',
    prefix: `(?:query|execute|sql)\\s*\\(\\s*['"\`](?:SELECT|INSERT|UPDATE|DELETE)[^'"\`]*\\+\\s*`,
    staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.'],
    message: '문자열 연결로 SQL 쿼리를 만들고 있습니다. SQL Injection에 취약합니다.',
    fix: 'Prepared Statement를 사용하세요.',
    languages: ['javascript', 'typescript'],
    severity: 'high',
  },
  {
    name: 'MongoDB Injection',
    prefix: `(?:find|findOne|updateOne|deleteOne)\\s*\\(\\s*\\{[^}]*:\\s*`,
    staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.'],
    message: '사용자 입력이 MongoDB 쿼리에 직접 들어가고 있습니다.',
    fix: 'mongo-sanitize로 입력을 검증하세요.',
    languages: ['javascript', 'typescript'],
    severity: 'high',
  },
  {
    name: 'Command Injection',
    prefix: `(?:spawn|spawnSync|system|popen|execSync|execFile)\\s*\\([^)]*`,
    staticSinks: ['req\\.', 'params\\.', 'body\\.', 'query\\.', 'input'],
    message: '사용자 입력이 시스템 명령어에 들어가고 있습니다. Command Injection에 취약합니다!',
    fix: '사용자 입력을 시스템 명령어에 사용하지 마세요.',
    languages: ['javascript', 'typescript', 'python'],
    severity: 'critical',
  },
];

const BARE_SQL_SINKS = new Set(['query', 'execute', 'sql', 'raw']);
const BARE_MONGO_SINKS = new Set(['find', 'findOne', 'updateOne', 'deleteOne', 'updateMany', 'deleteMany']);

export function scanInjection(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) {
      return scanInjectionAST(code, parsed);
    }
  }
  return scanInjectionRegex(code, lang);
}

function scanInjectionAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const taint = analyzeTaint(parsed);
  const issues: SecurityIssue[] = [];
  const sinks = [...SQL_SINKS, ...COMMAND_SINKS, ...MONGO_SINKS];

  walk(parsed.file, (node) => {
    if (!t.isCallExpression(node)) return;

    for (const def of sinks) {
      const m = matchInjectionSink(node, def);
      if (!m.match) continue;

      const arg = node.arguments[m.argIndex];
      if (arg && isTainted(arg as t.Node, taint)) {
        issues.push(toIssue(node, def, code));
        return;
      }
    }

    const calleeName = resolveCalleeName(node);
    if (!calleeName) return;

    const summary = taint.functionSummaries.get(calleeName);
    if (!summary) return;

    for (let i = 0; i < node.arguments.length; i++) {
      const paramName = summary.paramOrder[i];
      if (!paramName) continue;

      const flows = summary.paramFlows.get(paramName) ?? [];
      if (flows.length === 0) continue;

      if (isTainted(node.arguments[i] as t.Node, taint)) {
        const flowKinds = new Set(flows.map((f) => f.sinkKind));
        const def = sinks.find((d) => flowKinds.has(d.kind));
        if (def) {
          issues.push(toIssue(node, def, code));
          return;
        }
      }
    }
  });

  return issues;
}

function matchInjectionSink(call: t.CallExpression, def: SinkDefinition): SinkMatchResult {
  const base = matchSink(call, def);
  if (base.match) return base;
  if (!t.isIdentifier(call.callee)) return base;

  if (def.kind === 'sql' && BARE_SQL_SINKS.has(call.callee.name)) {
    return { match: true, argIndex: def.argIndex };
  }

  if (def.kind === 'mongo' && BARE_MONGO_SINKS.has(call.callee.name)) {
    return { match: true, argIndex: def.argIndex };
  }

  return base;
}

function resolveCalleeName(call: t.CallExpression): string | null {
  if (t.isIdentifier(call.callee)) return call.callee.name;
  if (t.isMemberExpression(call.callee) && t.isIdentifier(call.callee.property)) {
    return call.callee.property.name;
  }
  return null;
}

function scanInjectionRegex(code: string, lang: Language): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const lines = code.split('\n');
  const tainted = collectTaintedVars(code, lang);

  type Compiled = { name: string; regex: RegExp; message: string; fix: string; severity: 'critical' | 'high' };
  const compiled: Compiled[] = [];

  for (const p of STATIC_PATTERNS) {
    if (!p.languages.includes(lang)) continue;
    compiled.push({ name: p.name, regex: p.pattern, message: p.message, fix: p.fix, severity: p.severity ?? 'high' });
  }
  for (const p of TAINT_AWARE_PATTERNS) {
    if (!p.languages.includes(lang)) continue;
    const sinks = p.staticSinks.join('|') + taintAlternation(tainted);
    const source = `${p.prefix}(?:${sinks})${p.suffix ?? ''}`;
    compiled.push({
      name: p.name,
      regex: new RegExp(source, p.flags ?? 'gi'),
      message: p.message,
      fix: p.fix,
      severity: p.severity ?? 'high',
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
        type: p.name,
        severity: p.severity,
        message: p.message,
        fix: p.fix,
        line: lineNumber,
        match: match[0].slice(0, 100),
        owaspCategory: 'A03:2021 – Injection',
        cweId: 'CWE-89',
      });
    }
  }

  return issues;
}
