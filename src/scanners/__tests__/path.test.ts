import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPath } from '../path.js';

test('Direct readFile with req.body is flagged (baseline)', () => {
  const code = `fs.readFile(req.body.file, cb);`;
  const issues = scanPath(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Path Traversal Risk'));
});

test('R-9 (path variant): one-hop readFile is flagged', () => {
  const code = `
    const file = req.body.file;
    fs.readFile(file, cb);
  `;
  const issues = scanPath(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Path Traversal Risk'), 'expected one-hop detection');
});

test('R-21: path multi-hop is flagged', () => {
  const code = `
    const f = req.body.file;
    const norm = f;
    fs.readFile(norm, cb);
  `;
  const issues = scanPath(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Path Traversal Risk'));
});

test('function-param taint into fs sink is flagged', () => {
  const code = `
    function readUserFile(file) {
      fs.readFile(file, cb);
    }
    readUserFile(req.body.file);
  `;
  const issues = scanPath(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Path Traversal Risk'));
});

test('Path traversal pattern "../" is flagged', () => {
  const code = `const p = '../config';`;
  const issues = scanPath(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Path Traversal Pattern'));
});

test('Python pickle deserialization is flagged as critical', () => {
  const code = `data = pickle.load(open('x.pkl'))`;
  const issues = scanPath(code, 'python');
  const found = issues.find(i => i.type === 'Python Pickle Deserialization');
  assert.ok(found);
  assert.equal(found?.severity, 'critical');
});

test('chmod 777 is flagged', () => {
  const code = `fs.chmod(p, 0o777);`;
  const issues = scanPath(code, 'javascript');
  assert.ok(issues.some(i => i.type === 'Overly Permissive Mode'));
});

test('readFile in block comment is skipped (#7)', () => {
  const code = `/* fs.readFile(req.body.file, cb); */`;
  const issues = scanPath(code, 'javascript');
  assert.equal(issues.length, 0);
});

test('Empty input yields no issues', () => {
  assert.equal(scanPath('', 'javascript').length, 0);
});
