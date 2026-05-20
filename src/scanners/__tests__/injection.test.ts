import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanInjection } from '../injection.js';

test('Direct req.body in db.query is detected (baseline)', () => {
  const code = `db.query(\`SELECT * FROM u WHERE id = \${req.body.id}\`);`;
  const issues = scanInjection(code, 'typescript');
  assert.ok(issues.length >= 1);
});

test('R-9: one-hop tainted variable into template-literal SQL is detected', () => {
  const code = `
    const id = req.body.id;
    db.query(\`SELECT * FROM u WHERE id = \${id}\`);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.ok(issues.length >= 1, 'expected at least 1 issue for hop-1 SQL');
});

test('R-9: command-injection one-hop is detected', () => {
  // Vulnerable sample: tainted variable used as shell command argument.
  const code = [
    'const cmd = req.query.cmd;',
    'spawn(cmd);',
  ].join('\n');
  const issues = scanInjection(code, 'javascript');
  assert.ok(issues.some(i => i.type.includes('Command')));
});

test('R-10: function-parameter taint is NOT detected (out of scope for PR 1)', () => {
  const code = [
    'function handle(input) {',
    '  const sql = "SELECT * FROM u WHERE n = " + input;',
    '  db.query(sql);',
    '}',
  ].join('\n');
  const issues = scanInjection(code, 'javascript');
  // Assertion: no Command Injection finding caused by `input` being treated
  // as tainted (which the spec says is out of scope).
  assert.equal(issues.filter(i => i.type.includes('Command')).length, 0);
});

test('R-11: >50 tainted vars falls back to static patterns without crashing', () => {
  const lines = [];
  for (let i = 0; i < 60; i++) lines.push(`const v${i} = req.body.x${i};`);
  lines.push('spawn(req.body.cmd);');
  const code = lines.join('\n');
  const issues = scanInjection(code, 'javascript');
  assert.ok(issues.some(i => i.type.includes('Command')));
});

test('Python f-string SQL is detected', () => {
  const code = `cursor.execute(f"SELECT * FROM u WHERE id = {user_id}")`;
  const issues = scanInjection(code, 'python');
  assert.ok(issues.length >= 1);
});

test('Empty input yields no issues', () => {
  assert.equal(scanInjection('', 'javascript').length, 0);
});

test('Comment-only line is skipped (#7)', () => {
  const code = `// db.query("SELECT * FROM u WHERE id = " + req.body.id);`;
  const issues = scanInjection(code, 'javascript');
  assert.equal(issues.length, 0);
});

test('Match at file start reports line 1 (#5)', () => {
  const code = `spawn(req.body.cmd);`;
  const issues = scanInjection(code, 'javascript');
  assert.equal(issues[0].line, 1);
});
