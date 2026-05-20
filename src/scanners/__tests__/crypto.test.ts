import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCrypto } from '../crypto.js';

test('MD5 usage is flagged', () => {
  const code = `const h = crypto.createHash('md5');`;
  const issues = scanCrypto(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Weak Hash (MD5)'));
});

test('Math.random() is flagged', () => {
  const code = `const r = Math.random();`;
  const issues = scanCrypto(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Insecure Random (Math.random)'));
});

test('Direct req.body password storage is flagged (baseline)', () => {
  const code = `user.password = req.body.password;`;
  const issues = scanCrypto(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Plain Password Storage'));
});

test('R-9 (crypto variant): one-hop password storage is flagged', () => {
  const code = `
    const pw = req.body.password;
    user.password = pw;
  `;
  const issues = scanCrypto(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Plain Password Storage'), 'expected one-hop detection');
});

test('R-20: crypto multi-hop password storage is flagged', () => {
  const code = `
    const pw = req.body.password;
    const sanitized = pw;
    user.password = sanitized;
  `;
  const issues = scanCrypto(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Plain Password Storage'));
});

test('Object literal password storage remains flagged', () => {
  const code = `const user = { password: req.body.password };`;
  const issues = scanCrypto(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Plain Password Storage'));
});

test('Hash in block comment is skipped (#7)', () => {
  const code = `/* const h = crypto.createHash('md5'); */`;
  const issues = scanCrypto(code, 'javascript');
  assert.equal(issues.length, 0);
});

test('Empty input yields no issues', () => {
  assert.equal(scanCrypto('', 'javascript').length, 0);
});
