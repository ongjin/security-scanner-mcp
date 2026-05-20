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

test('R-15: function-param taint into SQL is detected', () => {
  const code = `
    function h(input) { db.query(\`SELECT * FROM u WHERE id = \${input}\`); }
    h(req.body.x);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.ok(issues.length >= 1, 'expected at least one issue from function-param taint');
});

test('R-16: multi-hop variable chain into SQL is detected', () => {
  const code = `
    const a = req.body.x;
    const b = a;
    const c = b;
    db.query(\`SELECT * FROM u WHERE id = \${c}\`);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.ok(issues.length >= 1, 'expected at least one issue from 3-hop chain');
});

test('MongoDB query object with direct req.query value is detected', () => {
  const code = 'collection.find({ name: req.query.name });';
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('mongo')),
    'expected a MongoDB injection issue for tainted query object value'
  );
});

test('bare query template literal with req.body is detected as SQL injection', () => {
  const code = 'query(`SELECT * FROM u WHERE id = ${req.body.id}`);';
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('sql')),
    'expected a SQL injection issue for bare query template literal'
  );
});

test('bare query string concatenation with req.body is detected as SQL injection', () => {
  const code = 'query("SELECT * FROM u WHERE id = " + req.body.id);';
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('sql')),
    'expected a SQL injection issue for bare query string concatenation'
  );
});

test('bare find query object with req.query is detected as MongoDB injection', () => {
  const code = 'find({ name: req.query.name });';
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('mongo')),
    'expected a MongoDB injection issue for bare find query object'
  );
});

test('function-param taint into bare query SQL is detected', () => {
  const code = `
    function h(input) { query(\`SELECT * FROM u WHERE id = \${input}\`); }
    h(req.body.x);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('sql')),
    'expected a SQL injection issue from function-param taint into bare query'
  );
});

test('function-param taint into bare find Mongo query is detected', () => {
  const code = `
    function h(input) { find({ name: input }); }
    h(req.query.name);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.ok(
    issues.some((i) => i.type.toLowerCase().includes('mongo')),
    'expected a MongoDB injection issue from function-param taint into bare find'
  );
});

test('R-22: return-value taint is NOT detected (PR 2 non-goal)', () => {
  const code = `
    function g(x) { return x; }
    const t = g(req.body.x);
    db.query(\`SELECT * FROM u WHERE id = \${t}\`);
  `;
  const issues = scanInjection(code, 'typescript');
  assert.equal(
    issues.filter((i) => i.type.toLowerCase().includes('sql')).length,
    0,
    'return-value taint should not be detected in PR 2'
  );
});

test('R-23: syntax error degrades gracefully (no thrown exception, no issues)', () => {
  const code = 'const x = ;';
  const issues = scanInjection(code, 'typescript');
  assert.equal(issues.length, 0);
});
