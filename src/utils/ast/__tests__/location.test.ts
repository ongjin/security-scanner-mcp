import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import { SQL_SINKS } from '../sinks.js';
import { toIssue } from '../location.js';

function firstCall(code: string): t.CallExpression {
  const ast = parseCode(code, 'javascript')!;
  let found: t.CallExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isCallExpression(node)) found = node;
  });
  return found!;
}

test('toIssue: returns SecurityIssue with line from node.loc', () => {
  const code = 'line1\nline2\ndb.query("SELECT 1");\nline4';
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.equal(issue.type, SQL_SINKS[0].name);
  assert.equal(issue.line, 3);
  assert.equal(issue.severity, 'high');
  assert.equal(issue.owaspCategory, 'A03:2021 – Injection');
  assert.equal(issue.cweId, 'CWE-89');
});

test('toIssue: match field contains the source snippet', () => {
  const code = 'db.query("SELECT 1");';
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.ok(issue.match);
  assert.ok(issue.match!.includes('db.query'));
});

test('toIssue: snippet is truncated to a sensible length', () => {
  const longArg = '"' + 'A'.repeat(200) + '"';
  const code = `db.query(${longArg});`;
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.ok(issue.match!.length <= 120);
});

test('toIssue: node without loc still returns an issue (line 0 fallback)', () => {
  const callee = t.memberExpression(t.identifier('db'), t.identifier('query'));
  const call = t.callExpression(callee, [t.stringLiteral('x')]);
  const issue = toIssue(call, SQL_SINKS[0], '');
  assert.equal(issue.type, SQL_SINKS[0].name);
  assert.equal(issue.line, 0);
});
