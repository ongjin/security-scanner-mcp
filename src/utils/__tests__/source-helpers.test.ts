import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lineOf } from '../source-helpers.js';

test('lineOf: index 0 returns line 1', () => {
  assert.equal(lineOf('abc', 0), 1);
});

test('lineOf: index immediately after \\n returns next line', () => {
  // "abc\ndef" — index 4 is 'd' on line 2.
  assert.equal(lineOf('abc\ndef', 4), 2);
});

test('lineOf: index on the newline itself stays on the line it terminates', () => {
  // "abc\ndef" — index 3 is '\n', which belongs to line 1.
  assert.equal(lineOf('abc\ndef', 3), 1);
});

test('lineOf: multi-line — match in the middle', () => {
  const code = 'a\nb\ncc\nd\ne';
  // a(0) \n(1) b(2) \n(3) c(4) c(5) \n(6) d(7) \n(8) e(9)
  assert.equal(lineOf(code, 4), 3);
});

test('lineOf: index past end saturates at last line', () => {
  assert.equal(lineOf('ab\ncd', 100), 2);
});

test('lineOf: negative index returns 1 (defensive)', () => {
  assert.equal(lineOf('abc', -1), 1);
});

test('lineOf: empty string returns 1', () => {
  assert.equal(lineOf('', 0), 1);
});

test('lineOf: leading newline — index 0 is line 1, index 1 is line 2', () => {
  assert.equal(lineOf('\nabc', 0), 1);
  assert.equal(lineOf('\nabc', 1), 2);
});
