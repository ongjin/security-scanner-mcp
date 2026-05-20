import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lineOf, isCommentLine, isInBlockComment } from '../source-helpers.js';

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

test('isCommentLine: JS/TS line comment', () => {
  assert.equal(isCommentLine('// hello', 'javascript'), true);
  assert.equal(isCommentLine('  // hello', 'typescript'), true);
});

test('isCommentLine: JS/TS block-comment opener and continuation', () => {
  assert.equal(isCommentLine('/* opener', 'javascript'), true);
  assert.equal(isCommentLine(' * continuation', 'javascript'), true);
  assert.equal(isCommentLine('*/ closer', 'javascript'), true);
});

test('isCommentLine: Python uses #', () => {
  assert.equal(isCommentLine('# comment', 'python'), true);
  assert.equal(isCommentLine('// not a python comment', 'python'), false);
});

test('isCommentLine: code line with inline comment is NOT a comment line', () => {
  assert.equal(isCommentLine('const x = 1; // tail', 'javascript'), false);
});

test('isCommentLine: blank line is not a comment', () => {
  assert.equal(isCommentLine('', 'javascript'), false);
  assert.equal(isCommentLine('   ', 'python'), false);
});

test('isInBlockComment: charIndex inside /* ... */ returns true', () => {
  assert.equal(isInBlockComment('a /* b */ c', 5), true);
});

test('isInBlockComment: charIndex outside any block returns false', () => {
  assert.equal(isInBlockComment('a /* b */ c', 0), false);
  assert.equal(isInBlockComment('a /* b */ c', 10), false);
});

test('isInBlockComment: multi-line block', () => {
  const code = 'before\n/*\n  inside\n*/\nafter';
  const insideIdx = code.indexOf('inside');
  const afterIdx = code.indexOf('after');
  assert.equal(isInBlockComment(code, insideIdx), true);
  assert.equal(isInBlockComment(code, afterIdx), false);
});

test('isInBlockComment: unterminated block treats rest of file as comment', () => {
  const code = 'a /* never closes';
  const idx = code.indexOf('never');
  assert.equal(isInBlockComment(code, idx), true);
});

test('isInBlockComment: nothing returns false', () => {
  assert.equal(isInBlockComment('plain code', 5), false);
});
