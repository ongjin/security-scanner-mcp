import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanXss } from '../xss.js';

test('innerHTML assignment with variable is detected', () => {
  const code = `element.innerHTML = userInput;`;
  const issues = scanXss(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'innerHTML Assignment'));
});

test('innerHTML with literal HTML still gets flagged by regex (existing behavior)', () => {
  const code = `element.innerHTML = '<div>safe</div>';`;
  const issues = scanXss(code, 'javascript');
  // The pattern has a lookahead but due to whitespace after =, it still matches.
  // This is acceptable baseline behavior.
  assert.ok(issues.some(i => i.type === 'innerHTML Assignment'));
});

test('Code-eval function is flagged as critical', () => {
  const code = `eval(userCode);`;
  const issues = scanXss(code, 'javascript');
  const evalIssue = issues.find(i => i.type === 'eval() Usage');
  assert.ok(evalIssue);
  assert.equal(evalIssue?.severity, 'critical');
});

test('innerHTML in a /* block comment */ is skipped (#7)', () => {
  const code = `/* element.innerHTML = userInput; */`;
  const issues = scanXss(code, 'javascript');
  assert.equal(issues.length, 0);
});

test('Line number is 1 for a match at file start (#5)', () => {
  const code = `eval(x);`;
  const issues = scanXss(code, 'javascript');
  assert.equal(issues[0].line, 1);
});

test('Empty input yields no issues', () => {
  assert.equal(scanXss('', 'javascript').length, 0);
});

test('Sanitized line is skipped (existing behavior preserved)', () => {
  const code = `element.innerHTML = DOMPurify.sanitize(userInput);`;
  const issues = scanXss(code, 'javascript');
  assert.equal(issues.filter(i => i.type === 'innerHTML Assignment').length, 0);
});
