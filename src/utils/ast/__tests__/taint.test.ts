import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCode } from '../parser.js';
import { analyzeTaint } from '../taint.js';

test('T-1: const a = req.body.x → taintedVars includes a', () => {
  const ast = parseCode('const a = req.body.x;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
});

test('T-2: multi-hop two-step', () => {
  const ast = parseCode('const a = req.body.x; const b = a;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
  assert.ok(state.taintedVars.has('b'));
});

test('T-3: transitive three-step', () => {
  const ast = parseCode(
    'const a = req.body.x; const b = a; const c = b;',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
  assert.ok(state.taintedVars.has('b'));
  assert.ok(state.taintedVars.has('c'));
});

test('T-4: process.env is trusted (a stays clean)', () => {
  const ast = parseCode('const a = process.env.X;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.equal(state.taintedVars.has('a'), false);
});

test('T-5: literal RHS does not taint', () => {
  const ast = parseCode('const a = "literal"; const b = a;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.equal(state.taintedVars.has('a'), false);
  assert.equal(state.taintedVars.has('b'), false);
});

test('fixed-point iteration reaches reverse-ordered chains longer than 50', () => {
  const reverseChain = Array.from(
    { length: 60 },
    (_, i) => `const v${60 - i} = v${59 - i};`
  ).join(' ');
  const ast = parseCode(`${reverseChain} const v0 = req.body.x;`, 'javascript')!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('v60'));
});
