import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanAuth } from '../auth.js';

test('JWT none algorithm is flagged as critical', () => {
  const code = `jwt.verify(token, secret, { algorithms: ['none'] });`;
  const issues = scanAuth(code, 'javascript');
  const found = issues.find(i => i.type === 'JWT No Algorithm Verification');
  assert.ok(found);
  assert.equal(found?.severity, 'critical');
});

test('CORS wildcard is flagged', () => {
  const code = `Access-Control-Allow-Origin = '*'`;
  const issues = scanAuth(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'CORS Allow All Origins'));
});

test('JWT in /* block comment */ is skipped (#7)', () => {
  const code = `/* algorithms: ['none'] */`;
  const issues = scanAuth(code, 'javascript');
  assert.equal(issues.length, 0);
});

test('Empty input yields no issues', () => {
  assert.equal(scanAuth('', 'javascript').length, 0);
});

test('Match at file start reports line 1 (#5)', () => {
  const code = `algorithms: ['none']`;
  const issues = scanAuth(code, 'javascript');
  assert.equal(issues[0].line, 1);
});
