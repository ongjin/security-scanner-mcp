import * as t from '@babel/types';
import type { SecurityIssue } from '../../types.js';

export type Severity = SecurityIssue['severity'];

export interface SinkDefinition {
  name: string;
  kind: 'sql' | 'command' | 'innerHTML' | 'fs' | 'mongo';
  matches: (call: t.CallExpression) => boolean;
  argIndex: number;
  severity: Severity;
  message: string;
  fix: string;
  owaspCategory?: string;
  cweId?: string;
}

export interface SinkMatchResult {
  match: boolean;
  argIndex: number;
}

function calleeMethodNameIn(call: t.CallExpression, names: Set<string>): boolean {
  if (!t.isMemberExpression(call.callee)) return false;
  return t.isIdentifier(call.callee.property) && names.has(call.callee.property.name);
}

function calleeIdentifierIn(call: t.CallExpression, names: Set<string>): boolean {
  return t.isIdentifier(call.callee) && names.has(call.callee.name);
}

const SQL_METHODS = new Set(['query', 'execute', 'sql', 'raw']);
const COMMAND_METHODS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync', 'execSync']);
const COMMAND_IDENTS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync', 'execSync', 'system', 'popen']);
const MONGO_METHODS = new Set(['find', 'findOne', 'updateOne', 'deleteOne', 'updateMany', 'deleteMany']);
const FS_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'unlink', 'unlinkSync', 'rmdir', 'rmdirSync', 'rm', 'rmSync',
  'createReadStream', 'createWriteStream', 'readdir', 'readdirSync',
  'mkdir', 'mkdirSync', 'access', 'accessSync', 'stat', 'statSync',
]);

export const SQL_SINKS: SinkDefinition[] = [
  {
    name: 'SQL query with user input',
    kind: 'sql',
    matches: (call) => calleeMethodNameIn(call, SQL_METHODS),
    argIndex: 0,
    severity: 'high',
    message: '사용자 입력이 SQL 쿼리에 직접 들어가고 있습니다.',
    fix: 'Prepared Statement 또는 Parameterized Query를 사용하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-89',
  },
];

export const COMMAND_SINKS: SinkDefinition[] = [
  {
    name: 'Command Injection',
    kind: 'command',
    matches: (call) =>
      calleeIdentifierIn(call, COMMAND_IDENTS) || calleeMethodNameIn(call, COMMAND_METHODS),
    argIndex: 0,
    severity: 'critical',
    message: '사용자 입력이 시스템 명령어 호출에 흘러들어갑니다. Command Injection!',
    fix: '사용자 입력을 시스템 명령에 사용하지 마세요. 꼭 필요하면 화이트리스트 검증을 하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-78',
  },
];

export const MONGO_SINKS: SinkDefinition[] = [
  {
    name: 'MongoDB Injection',
    kind: 'mongo',
    matches: (call) => calleeMethodNameIn(call, MONGO_METHODS),
    argIndex: 0,
    severity: 'high',
    message: '사용자 입력이 MongoDB 쿼리 객체에 들어갑니다.',
    fix: 'mongo-sanitize 또는 스키마 검증으로 입력을 제한하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-943',
  },
];

export const FS_SINKS: SinkDefinition[] = [
  {
    name: 'Path Traversal Risk',
    kind: 'fs',
    matches: (call) => calleeMethodNameIn(call, FS_METHODS),
    argIndex: 0,
    severity: 'critical',
    message: '사용자 입력으로 파일 경로를 구성하고 있습니다.',
    fix: 'path.basename()으로 정규화하거나 허용 디렉토리를 화이트리스트로 제한하세요.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cweId: 'CWE-22',
  },
];

export const INNERHTML_SINKS: SinkDefinition[] = [
  {
    name: 'innerHTML with non-literal',
    kind: 'innerHTML',
    matches: () => false,
    argIndex: -1,
    severity: 'high',
    message: 'innerHTML에 문자열 리터럴이 아닌 값을 할당하고 있습니다. XSS 위험.',
    fix: 'textContent를 사용하거나 DOMPurify로 sanitize하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-79',
  },
];

export function matchSink(call: t.CallExpression, def: SinkDefinition): SinkMatchResult {
  if (!def.matches(call)) return { match: false, argIndex: -1 };
  return { match: true, argIndex: def.argIndex };
}

export function matchInnerHtmlAssignment(
  node: t.AssignmentExpression
): t.Expression | null {
  if (node.operator !== '=') return null;
  if (!t.isMemberExpression(node.left)) return null;
  if (!t.isIdentifier(node.left.property)) return null;
  if (node.left.property.name !== 'innerHTML' && node.left.property.name !== 'outerHTML') return null;
  return node.right;
}
