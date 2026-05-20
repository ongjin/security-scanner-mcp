import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import { isUserInputSource } from '../sources.js';

function firstMemberExpression(code: string): t.MemberExpression | null {
  const ast = parseCode(code, 'javascript')!;
  let found: t.MemberExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isMemberExpression(node)) found = node;
  });
  return found;
}

test('isUserInputSource: req.body.x is a source', () => {
  const me = firstMemberExpression('const x = req.body.x;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: req.query.foo is a source', () => {
  const me = firstMemberExpression('const x = req.query.foo;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: req.params.id is a source', () => {
  const me = firstMemberExpression('const x = req.params.id;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: request.body is a source (named export style)', () => {
  const me = firstMemberExpression('const x = request.body;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: ctx.request.body is a source (Koa style)', () => {
  const ast = parseCode('const x = ctx.request.body;', 'javascript')!;
  let outerMember: t.MemberExpression | null = null;
  walk(ast.file, (node) => {
    if (t.isVariableDeclarator(node) && t.isMemberExpression(node.init)) {
      outerMember = node.init;
    }
  });
  assert.equal(isUserInputSource(outerMember!), true);
});

test('isUserInputSource: event.body is a source (Lambda style)', () => {
  const me = firstMemberExpression('const x = event.body;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: process.env.X is NOT a source (trusted)', () => {
  const me = firstMemberExpression('const x = process.env.X;')!;
  assert.equal(isUserInputSource(me), false);
});

test('isUserInputSource: process.argv IS a source', () => {
  const me = firstMemberExpression('const x = process.argv;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: foo.bar is not a source', () => {
  const me = firstMemberExpression('const x = foo.bar;')!;
  assert.equal(isUserInputSource(me), false);
});

test('isUserInputSource: non-MemberExpression returns false', () => {
  assert.equal(isUserInputSource(t.identifier('x')), false);
  assert.equal(isUserInputSource(t.stringLiteral('hi')), false);
});
