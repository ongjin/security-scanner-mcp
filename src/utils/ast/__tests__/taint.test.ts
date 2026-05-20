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

test('T-6: function h(input) with SQL sink → paramFlows.input has sql sink', () => {
  const ast = parseCode(
    'function h(input) { db.query(`SELECT * FROM u WHERE id = ${input}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h');
  assert.ok(summary, 'expected summary for h');
  const flows = summary!.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});

test('T-7: only the referenced param shows a flow', () => {
  const ast = parseCode(
    'function h(a, b) { db.query(`SELECT * FROM u WHERE id = ${b}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const bFlows = summary.paramFlows.get('b') ?? [];
  const aFlows = summary.paramFlows.get('a') ?? [];
  assert.ok(bFlows.some((f) => f.sinkKind === 'sql'));
  assert.equal(aFlows.length, 0);
});

test('T-8: function-body multi-hop reaches sink', () => {
  const ast = parseCode(
    'function h(input) { const x = input; db.query(`... ${x}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const flows = summary.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});

test('T-9: empty function body has empty paramFlows', () => {
  const ast = parseCode('function h(a, b) {}', 'javascript')!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  assert.equal(summary.paramFlows.get('a')?.length ?? 0, 0);
  assert.equal(summary.paramFlows.get('b')?.length ?? 0, 0);
});

test('T-10: arrow function assigned to variable is recognized', () => {
  const ast = parseCode(
    'const h = (input) => db.query(`... ${input}`);',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h');
  assert.ok(summary, 'expected summary for h');
  const flows = summary!.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});

test('function-summary: unknown call return does not carry argument colors', () => {
  const ast = parseCode(
    'function h(input) { const x = sanitize(input); db.query(x); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const flows = summary.paramFlows.get('input') ?? [];
  assert.equal(flows.some((f) => f.sinkKind === 'sql'), false);
});

test('function-summary: conditional test is not sink argument data flow', () => {
  const ast = parseCode(
    "function h(input) { db.query(input ? 'SELECT 1' : 'SELECT 2'); }",
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const flows = summary.paramFlows.get('input') ?? [];
  assert.equal(flows.some((f) => f.sinkKind === 'sql'), false);
});
