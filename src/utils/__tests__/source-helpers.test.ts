import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lineOf, isCommentLine, isInBlockComment, stripInlineComments, isPlaceholderValue } from '../source-helpers.js';

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

test('stripInlineComments: removes JS // tail', () => {
  assert.equal(stripInlineComments('const x = 1; // tail', 'javascript'), 'const x = 1; ');
});

test('stripInlineComments: removes Python # tail', () => {
  assert.equal(stripInlineComments('x = 1  # tail', 'python'), 'x = 1  ');
});

test('stripInlineComments: preserves // inside double-quoted string', () => {
  assert.equal(
    stripInlineComments('const url = "http://example.com";', 'javascript'),
    'const url = "http://example.com";'
  );
});

test('stripInlineComments: preserves // inside single-quoted string', () => {
  assert.equal(
    stripInlineComments(`const url = 'http://example.com';`, 'javascript'),
    `const url = 'http://example.com';`
  );
});

test('stripInlineComments: preserves // inside template literal', () => {
  assert.equal(
    stripInlineComments('const url = `http://example.com`;', 'javascript'),
    'const url = `http://example.com`;'
  );
});

test('stripInlineComments: line without comment is returned unchanged', () => {
  assert.equal(stripInlineComments('const x = 1;', 'javascript'), 'const x = 1;');
});

test('stripInlineComments: handles escaped quote inside string', () => {
  const input = `const s = "a\\"// not a comment";`;
  assert.equal(stripInlineComments(input, 'javascript'), input);
});

test('isPlaceholderValue: obvious placeholder phrases', () => {
  assert.equal(isPlaceholderValue('your_api_key_here'), true);
  assert.equal(isPlaceholderValue('<your-token>'), true);
  assert.equal(isPlaceholderValue('CHANGEME'), true);
  assert.equal(isPlaceholderValue('example-key'), true);
  assert.equal(isPlaceholderValue('placeholder-value'), true);
  assert.equal(isPlaceholderValue('dummy123'), true);
});

test('isPlaceholderValue: all-same-character runs', () => {
  assert.equal(isPlaceholderValue('xxxxxxxx'), true);
  assert.equal(isPlaceholderValue('00000000'), true);
});

test('isPlaceholderValue: low-entropy strings', () => {
  assert.equal(isPlaceholderValue('aaaaaaaabbbbbbbb'), true);
});

test('isPlaceholderValue: real-looking AWS key is NOT placeholder', () => {
  assert.equal(isPlaceholderValue('AKIAIOSFODNN7EXAMPLE'), true);
  assert.equal(isPlaceholderValue('AKIAJ7VKQ3X5C9Z2N1W4'), false);
});

test('isPlaceholderValue: short random-looking strings are not placeholders', () => {
  assert.equal(isPlaceholderValue('Xy3Lk9mP2Qr8Wn5T'), false);
});

test('isPlaceholderValue: empty string is not a placeholder', () => {
  assert.equal(isPlaceholderValue(''), false);
});
