import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Node } from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';

test('walk: visits every node in a simple program', () => {
  const ast = parseCode('const x = 1;', 'javascript')!;
  const seen: string[] = [];
  walk(ast.file, (node) => {
    seen.push(node.type);
  });
  // File -> Program -> VariableDeclaration -> VariableDeclarator -> Identifier + NumericLiteral
  assert.ok(seen.includes('Program'));
  assert.ok(seen.includes('VariableDeclaration'));
  assert.ok(seen.includes('VariableDeclarator'));
  assert.ok(seen.includes('Identifier'));
  assert.ok(seen.includes('NumericLiteral'));
});

test('walk: visitor returning false skips children', () => {
  const ast = parseCode('const x = { a: 1, b: 2 };', 'javascript')!;
  const seen: string[] = [];
  walk(ast.file, (node) => {
    seen.push(node.type);
    if (node.type === 'ObjectExpression') return false; // skip children
  });
  assert.ok(seen.includes('ObjectExpression'));
  // Object property values should NOT be visited
  assert.equal(seen.filter((n) => n === 'ObjectProperty').length, 0);
});

test('walk: parent and ancestors are passed to visitor', () => {
  const ast = parseCode('const x = 1;', 'javascript')!;
  let parentForIdentifier: Node | null | undefined;
  let ancestorsForIdentifier: Node[] | undefined;
  walk(ast.file, (node, parent, ancestors) => {
    if (node.type === 'Identifier' && (node as any).name === 'x') {
      parentForIdentifier = parent;
      ancestorsForIdentifier = ancestors;
    }
  });
  assert.equal(parentForIdentifier?.type, 'VariableDeclarator');
  assert.ok(ancestorsForIdentifier);
  assert.ok(ancestorsForIdentifier!.some((n) => n.type === 'VariableDeclaration'));
});

test('walk: handles array children (e.g. function params)', () => {
  const ast = parseCode('function f(a, b, c) {}', 'javascript')!;
  const paramNames: string[] = [];
  walk(ast.file, (node) => {
    if (
      node.type === 'Identifier' &&
      ['a', 'b', 'c'].includes(node.name)
    ) {
      paramNames.push(node.name);
    }
  });
  assert.deepEqual(paramNames, ['a', 'b', 'c']);
});

test('walk: ignores Babel comment metadata nodes', () => {
  const ast = parseCode('/* lead */ const x = 1; // trail\n', 'javascript')!;
  const seen: string[] = [];
  walk(ast.file, (node) => {
    seen.push(node.type);
  });
  assert.equal(seen.includes('CommentBlock'), false);
  assert.equal(seen.includes('CommentLine'), false);
});

test('walk: empty program does not throw', () => {
  const ast = parseCode('', 'javascript')!;
  walk(ast.file, () => {}); // no-op visitor
});
