import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanXss } from '../xss.js';

test('innerHTML assignment with variable is detected', () => {
  const code = `element.innerHTML = userInput;`;
  const issues = scanXss(code, 'javascript');
  assert.ok(issues.some((i) => i.type.toLowerCase().includes('innerhtml')));
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
  assert.equal(
    issues.filter((i) => i.type.toLowerCase().includes('innerhtml')).length,
    0
  );
});

test('R-17: literal HTML on innerHTML is NOT flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>';`;
  const issues = scanXss(code, 'typescript');
  assert.equal(
    issues.filter((i) => i.type.toLowerCase().includes('innerhtml')).length,
    0
  );
});

test('R-18: identifier RHS on innerHTML IS flagged', () => {
  const code = `el.innerHTML = userInput;`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type.toLowerCase().includes('innerhtml')));
});

test('R-18: identifier RHS on innerHTML preserves exact issue type', () => {
  const code = `el.innerHTML = userInput;`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('JS/TS parse-failure fallback does not report literal innerHTML', () => {
  const code = `el.innerHTML = '<div>safe</div>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(
    issues.filter((i) => i.type.toLowerCase().includes('innerhtml')).length,
    0
  );
});

test('parse-failure dynamic innerHTML assignment reports innerHTML Assignment', () => {
  const code = `el.innerHTML = userInput; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure literal innerHTML assignment remains suppressed', () => {
  const code = `el.innerHTML = '<div>safe</div>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure parenthesized literal innerHTML assignment remains suppressed', () => {
  const code = `el.innerHTML = ('<div>safe</div>'); const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure multiline dynamic innerHTML assignment reports innerHTML Assignment', () => {
  const code = `el.innerHTML =\n  userInput; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure multiline static-prefix dynamic innerHTML assignment reports innerHTML Assignment', () => {
  const code = `el.innerHTML = '<div>'
  + userInput; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure as-expression with dynamic continuation reports innerHTML Assignment', () => {
  const code = `el.innerHTML = '<div>' as string + userInput; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure satisfies-expression with dynamic continuation reports innerHTML Assignment', () => {
  const code = `el.innerHTML = '<div>' satisfies string + userInput; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure innerHTML literal containing entity semicolon remains suppressed', () => {
  const code = `el.innerHTML = '<span>&nbsp;</span>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure innerHTML literal containing style semicolon remains suppressed', () => {
  const code = `el.innerHTML = '<div style="color:red;"></div>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure parenthesized literal containing style semicolon remains suppressed', () => {
  const code = `el.innerHTML = ('<div style="color:red;"></div>'); const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure parenthesized as-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = ('<div>safe</div>') as string; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure parenthesized satisfies-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = ('<div>safe</div>') satisfies string; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure parenthesized non-null string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = ('<div>safe</div>')!; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure as-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>' as string; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure satisfies-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>' satisfies string; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure non-null string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>'!; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure angle-asserted string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = <string>'<div>safe</div>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('parse-failure dynamic TypeScript wrapper RHS on innerHTML is still reported', () => {
  const code = `el.innerHTML = userInput as string; const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure parenthesized dynamic RHS on innerHTML is still reported', () => {
  const code = `el.innerHTML = (userInput); const =`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('parse-failure escaped template interpolation text on innerHTML is not flagged', () => {
  const code = 'el.innerHTML = `\\${user}`; const =';
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('TypeScript as-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>' as string;`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('TypeScript satisfies-expression string literal RHS on innerHTML is not flagged', () => {
  const code = `el.innerHTML = '<div>safe</div>' satisfies string;`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('repeated eval calls on one line are both reported', () => {
  const code = `eval(a); eval(b);`;
  const issues = scanXss(code, 'javascript');
  assert.equal(issues.filter((i) => i.type === 'eval() Usage').length, 2);
});

test('outerHTML assignment remains regex-owned and is not reported as innerHTML', () => {
  const code = `el.outerHTML = userInput;`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'outerHTML Assignment').length, 1);
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
  assert.equal(issues.filter((i) => i.type === 'innerHTML with non-literal').length, 0);
});

test('computed identifier property is not treated as innerHTML', () => {
  const code = `el[innerHTML] = userInput;`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
});

test('computed string-literal innerHTML property is reported', () => {
  const code = `el['innerHTML'] = userInput;`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'innerHTML Assignment'));
});

test('dangerouslySetInnerHTML is preserved after AST regex merge', () => {
  const code = `const x = <div dangerouslySetInnerHTML={{ __html: userHtml }} />;`;
  const issues = scanXss(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'dangerouslySetInnerHTML'));
});

test('parse-failure fallback suppresses literal innerHTML but preserves dangerouslySetInnerHTML', () => {
  const code = `const x = <div dangerouslySetInnerHTML={{ __html: userHtml }} />; el.innerHTML = '<div>safe</div>'; const =`;
  const issues = scanXss(code, 'typescript');
  assert.equal(issues.filter((i) => i.type === 'innerHTML Assignment').length, 0);
  assert.ok(issues.some((i) => i.type === 'dangerouslySetInnerHTML'));
});

test('R-24: Python code-eval input uses regex fallback', () => {
  const code = 'result = eval(user_input)';
  const issues = scanXss(code, 'python');
  assert.ok(issues.length >= 1);
});
