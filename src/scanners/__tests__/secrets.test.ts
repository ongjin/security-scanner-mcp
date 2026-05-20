import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecrets } from '../secrets.js';

const REAL_KEY = 'AKIAJ7VKQ3X5C9Z2N1W4';

test('R-1: AWS key in plain code is detected', () => {
  const code = `const apiKey = "${REAL_KEY}";`;
  const issues = scanSecrets(code);
  assert.ok(issues.some(i => i.type === 'AWS Access Key'), 'must detect AWS Access Key');
  assert.ok(issues.some(i => i.type === 'AWS Access Key' && i.line === 1));
});

test('R-2: AWS key in variable named "test_api_key" is still detected (#4 fix)', () => {
  const code = `const test_api_key = "${REAL_KEY}";`;
  const issues = scanSecrets(code);
  assert.ok(issues.some(i => i.type === 'AWS Access Key'), 'must NOT be skipped due to var name containing "test"');
});

test('R-3: placeholder-looking value is skipped', () => {
  const code = `const apiKey = "your_api_key_here_xxxxxxx";`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 0);
});

test('R-4: key inside // line comment is skipped', () => {
  const code = `// example: const k = "${REAL_KEY}"`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 0);
});

test('R-5: key inside /* block comment */ is skipped (#7 fix)', () => {
  const code = `/*\n  sample: ${REAL_KEY}\n*/`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 0);
});

test('R-6: key inside inline-comment tail is skipped (#7 fix)', () => {
  const code = `const x = 1; // ${REAL_KEY}`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 0);
});

test('R-7: key on Nth line reports line N', () => {
  const code = `line1\nline2\nconst k = "${REAL_KEY}";\nline4`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].line, 3);
});

test('R-8: match at index 0 reports line 1 (#5 regression)', () => {
  const code = `${REAL_KEY} = 1`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].line, 1);
});

test('Empty input yields no issues', () => {
  assert.equal(scanSecrets('').length, 0);
});

test('Multiple secrets in one source are all reported', () => {
  const code = `
    const a = "${REAL_KEY}";
    const b = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
  `;
  const issues = scanSecrets(code);
  assert.ok(issues.some(i => i.type === 'AWS Access Key'));
  assert.ok(issues.some(i => i.type === 'GitHub Token'));
});

test('Secret value is masked in the reported match', () => {
  const code = `const k = "${REAL_KEY}";`;
  const issues = scanSecrets(code);
  assert.equal(issues.length, 1);
  assert.ok(issues[0].match?.includes('****'));
});
