import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import {
  SQL_SINKS, COMMAND_SINKS, INNERHTML_SINKS, FS_SINKS, MONGO_SINKS, matchSink,
  matchInnerHtmlAssignment,
} from '../sinks.js';

function firstCall(code: string): t.CallExpression | null {
  const ast = parseCode(code, 'javascript')!;
  let found: t.CallExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isCallExpression(node)) found = node;
  });
  return found;
}

function firstAssignment(code: string): t.AssignmentExpression | null {
  const ast = parseCode(code, 'javascript')!;
  let found: t.AssignmentExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isAssignmentExpression(node)) found = node;
  });
  return found;
}

test('SQL: db.query(...) matches a SQL sink', () => {
  const call = firstCall('db.query("SELECT * FROM u");')!;
  const m = SQL_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m, 'expected a SQL sink match');
});

test('SQL: connection.execute(...) matches a SQL sink', () => {
  const call = firstCall('connection.execute("SELECT 1");')!;
  const m = SQL_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('SQL: unrelated function call does not match', () => {
  const call = firstCall('console.log("hello");')!;
  const matched = SQL_SINKS.some(s => matchSink(call, s).match);
  assert.equal(matched, false);
});

test('Command: spawn(...) matches', () => {
  const call = firstCall('spawn("ls", ["/"]);')!;
  const m = COMMAND_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('Command: child_process.spawn(...) matches', () => {
  const call = firstCall('child_process.spawn("ls");')!;
  const m = COMMAND_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('Command: execSync(...) matches', () => {
  const call = firstCall('execSync("ls");')!;
  const m = COMMAND_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('Command: child_process.execSync(...) matches', () => {
  const call = firstCall('child_process.execSync("ls");')!;
  const m = COMMAND_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('Mongo: collection.find(query) matches', () => {
  const call = firstCall('collection.find({ name: "x" });')!;
  const m = MONGO_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('FS: fs.readFile(...) matches', () => {
  const call = firstCall('fs.readFile("/tmp/foo");')!;
  const m = FS_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('FS: fs.mkdir(...) matches', () => {
  const call = firstCall('fs.mkdir("/tmp/foo");')!;
  const m = FS_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('FS: fs.access(...) matches', () => {
  const call = firstCall('fs.access("/tmp/foo");')!;
  const m = FS_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('FS: fs.stat(...) matches', () => {
  const call = firstCall('fs.stat("/tmp/foo");')!;
  const m = FS_SINKS.find(s => matchSink(call, s).match);
  assert.ok(m);
});

test('FS: fs.chmod with permissive mode is a separate concern, not in FS_SINKS taint sinks', () => {
  const call = firstCall('fs.chmod(p, 0o777);')!;
  const matched = FS_SINKS.some(s => matchSink(call, s).match);
  assert.equal(matched, false, 'fs.chmod is not a taint sink');
});

test('matchInnerHtmlAssignment: returns RHS for innerHTML assignment', () => {
  const assignment = firstAssignment('el.innerHTML = userInput;')!;
  const rhs = matchInnerHtmlAssignment(assignment);
  assert.ok(t.isIdentifier(rhs));
  assert.equal(rhs.name, 'userInput');
  assert.equal(INNERHTML_SINKS[0].kind, 'innerHTML');
});

test('matchInnerHtmlAssignment: returns RHS for outerHTML assignment', () => {
  const assignment = firstAssignment('el.outerHTML = userInput;')!;
  const rhs = matchInnerHtmlAssignment(assignment);
  assert.ok(t.isIdentifier(rhs));
  assert.equal(rhs.name, 'userInput');
});

test('matchInnerHtmlAssignment: non-equals assignment returns null', () => {
  const assignment = firstAssignment('el.innerHTML += userInput;')!;
  assert.equal(matchInnerHtmlAssignment(assignment), null);
});

test('matchInnerHtmlAssignment: non-inner or outerHTML property returns null', () => {
  const assignment = firstAssignment('el.textContent = userInput;')!;
  assert.equal(matchInnerHtmlAssignment(assignment), null);
});

test('matchSink: returns argIndex from the SinkDefinition', () => {
  const call = firstCall('db.query("SELECT 1");')!;
  const def = SQL_SINKS[0];
  const m = matchSink(call, def);
  assert.ok(m.match);
  assert.equal(m.argIndex, 0);
});
