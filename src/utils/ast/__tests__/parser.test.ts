import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCode } from '../parser.js';

test('parseCode: valid JavaScript returns a ParseResult', () => {
  const result = parseCode('const x = 1;', 'javascript');
  assert.ok(result);
  assert.equal(result?.language, 'javascript');
  assert.equal(result?.file.type, 'File');
});

test('parseCode: valid TypeScript with type annotation', () => {
  const result = parseCode('const x: number = 1;', 'typescript');
  assert.ok(result);
  assert.equal(result?.language, 'typescript');
});

test('parseCode: JSX in TypeScript', () => {
  const result = parseCode('const el = <div>hello</div>;', 'typescript');
  assert.ok(result);
});

test('parseCode: syntax error returns null (does not throw)', () => {
  const result = parseCode('const x = ;', 'javascript');
  assert.equal(result, null);
});

test('parseCode: empty string returns a ParseResult with empty program', () => {
  const result = parseCode('', 'javascript');
  assert.ok(result);
  assert.equal(result?.file.program.body.length, 0);
});

test('parseCode: unknown language defaults safely (treats as javascript)', () => {
  const result = parseCode('const x = 1;', 'rust' as any);
  assert.ok(result);
  assert.equal(result?.language, 'javascript');
});
