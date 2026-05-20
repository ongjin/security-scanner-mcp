# AST Migration & Function-Aware Taint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace regex-based detection in the 5 call-site scanners (injection, xss, crypto, auth, path) with AST-based detection for JS/TS inputs. Introduce single-file taint analysis with function-parameter propagation. Python/Java/Go inputs continue using the PR 1 regex path. Ship as 1.2.0.

**Architecture:** New `src/utils/ast/` module with focused submodules (`parser`, `traverse`, `taint`, `sources`, `sinks`, `location`). Each scanner routes by language: JS/TS → AST path; everything else → PR 1 regex path. Taint analysis runs a two-pass walk over the AST: a fixed-point pass for top-level variable taint, then a per-function pass that produces summaries mapping parameters to the sinks they reach. The existing dead `src/utils/ast-parser.ts` is removed in the same PR.

**Tech Stack:** TypeScript (ESM, "type":"module"), node:test, tsx loader, `@babel/parser`, `@babel/types`. No new deps.

**Spec:** `docs/superpowers/specs/2026-05-20-ast-migration-design.md`

---

## File Structure

### New files

| Path | Responsibility |
|---|---|
| `src/utils/ast/parser.ts` | Babel-parser wrapper. `parseCode(code, language)` returns `ParseResult` or `null` on syntax error. Never throws. |
| `src/utils/ast/traverse.ts` | Generic AST walker. `walk(node, visitor)` with parent/ancestor tracking. Visitor can return `false` to skip children. |
| `src/utils/ast/sources.ts` | Tainted-source matchers. Recognizes `req.body.x`, `req.query.x`, `request.form`, `process.argv`, etc. |
| `src/utils/ast/sinks.ts` | Per-category sink definitions for SQL, command, DOM-write, FS, and Mongo APIs. |
| `src/utils/ast/taint.ts` | Core taint analysis. `analyzeTaint(ast)` returns `TaintState`; `isTainted(node, state)` checks whether an expression is tainted. Builds `functionSummaries` for function-arg propagation. |
| `src/utils/ast/location.ts` | AST node to `SecurityIssue` converter. |
| `src/utils/ast/index.ts` | Barrel export of the public API. |
| `src/utils/ast/__tests__/parser.test.ts` | TDD harness for parser. |
| `src/utils/ast/__tests__/traverse.test.ts` | TDD harness for walker. |
| `src/utils/ast/__tests__/sources.test.ts` | TDD harness for source matchers. |
| `src/utils/ast/__tests__/sinks.test.ts` | TDD harness for sink matchers. |
| `src/utils/ast/__tests__/taint.test.ts` | T-1..T-10 from the spec. |
| `src/utils/ast/__tests__/location.test.ts` | TDD harness for the issue converter. |

### Modified files

| Path | Why |
|---|---|
| `package.json` | Extend test discovery glob to match `src/*/*/__tests__/*.test.ts`; bump version to 1.2.0 in the release task. |
| `src/scanners/injection.ts` | Split into AST and regex variants. Public `scanInjection` routes by language. |
| `src/scanners/xss.ts` | Same shape. |
| `src/scanners/crypto.ts` | Same shape. |
| `src/scanners/auth.ts` | Same shape. |
| `src/scanners/path.ts` | Same shape. |
| `src/scanners/__tests__/injection.test.ts` | Add R-15, R-16, R-22, R-23. |
| `src/scanners/__tests__/xss.test.ts` | Add R-17, R-18, R-24. Remove the PR 1 limitation acknowledgement comment from the literal-HTML test. |
| `src/scanners/__tests__/crypto.test.ts` | Add R-20. |
| `src/scanners/__tests__/auth.test.ts` | Add R-19. Remove the PR 1 limitation comment. |
| `src/scanners/__tests__/path.test.ts` | Add R-21. |
| `CHANGELOG.md` | Add 1.2.0 section. |

### Deleted files

| Path | Why |
|---|---|
| `src/utils/ast-parser.ts` | Dead infrastructure replaced by `src/utils/ast/`. No internal callers. |

---

## Working Conventions

- **Imports use `.js` extensions** matching existing TypeScript ESM convention.
- **Run a single test file** with `npm test -- <path>`.
- **Commit per task.** Each task ends with a green test run AND a commit.
- All commits end with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- The repo has a security-reminder hook that warns on first write of files containing specific dangerous-pattern substrings. The plan's test fixtures intentionally include these because the scanner needs to detect them. If a write fails with a hook warning, retry — the second write succeeds.

---

## Task 1: Extend test discovery glob

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Inspect current test script**

Run:
```bash
node -p "require('./package.json').scripts.test"
```
Expected output:
```
node --import tsx --test src/*/__tests__/*.test.ts
```

- [ ] **Step 2: Update the script to include the deeper glob**

Edit `package.json`. Change:
```json
"test": "node --import tsx --test src/*/__tests__/*.test.ts",
```
to:
```json
"test": "node --import tsx --test src/*/__tests__/*.test.ts src/*/*/__tests__/*.test.ts",
```

The second glob matches `src/utils/ast/__tests__/*.test.ts` (and `src/iac-scanners/__tests__/*.test.ts` was already matched by the first; nothing else lives 2 levels deep right now, but the pattern is forward-compatible).

- [ ] **Step 3: Verify the existing test suite still runs**

Run:
```bash
npm test
```
Expected: all 100 PR-1 tests still pass. If `sh` keeps the second glob literal because no matching files exist yet, that's fine — `node --test` ignores unknown positional args that don't exist… actually no, it errors. Mitigation: add the new glob only when we're about to create files under it. Or, equivalently: run `mkdir -p src/utils/ast/__tests__` and `touch src/utils/ast/__tests__/.gitkeep` first. We choose the latter — create the dir before the script update.

Revised order: create the directory first, then update the script.

```bash
mkdir -p src/utils/ast/__tests__
touch src/utils/ast/__tests__/.gitkeep
```
Then update `package.json` and re-run `npm test`. The second glob now has at least one expansion candidate (the `.gitkeep` is ignored because it doesn't match `*.test.ts`, but the directory exists so the shell glob doesn't fall through to the literal).

Wait — if no `*.test.ts` files exist yet under `src/*/*/__tests__/`, the `sh` glob still has nothing to expand to. The shell will pass the literal string `src/*/*/__tests__/*.test.ts` to node. `node --test` will treat it as a filename and complain "no such file."

Cleanest fix: write a minimal smoke test FIRST in the new location, then update the script. The smoke test is replaced by real tests in Task 2 anyway.

- [ ] **Step 4: Create a temporary smoke test in the new location**

```bash
mkdir -p src/utils/ast/__tests__
```

Create `src/utils/ast/__tests__/_smoke.test.ts`:
```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('ast test directory discovery works', () => {
  assert.equal(1 + 1, 2);
});
```

- [ ] **Step 5: Update `package.json` test script**

```json
"test": "node --import tsx --test src/*/__tests__/*.test.ts src/*/*/__tests__/*.test.ts",
```

- [ ] **Step 6: Run the suite**

```bash
npm test
```
Expected: 101 tests pass (100 PR-1 + 1 smoke).

- [ ] **Step 7: Commit**

```bash
git add package.json src/utils/ast/__tests__/_smoke.test.ts
git commit -m "$(cat <<'EOF'
chore(test): extend test discovery to src/utils/ast/__tests__

Adds a second glob to the node:test discovery list so tests in deeper
directories (specifically src/utils/ast/__tests__) are picked up. The
new src/utils/ast/ module is built in subsequent tasks.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `parser.ts` — babel-parser wrapper

**Files:**
- Create: `src/utils/ast/parser.ts`
- Create: `src/utils/ast/__tests__/parser.test.ts`
- Delete: `src/utils/ast/__tests__/_smoke.test.ts` (replaced by real tests)

- [ ] **Step 1: Delete the smoke test**

```bash
rm src/utils/ast/__tests__/_smoke.test.ts
```

- [ ] **Step 2: Write failing tests**

Create `src/utils/ast/__tests__/parser.test.ts`:
```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCode } from '../parser.js';

test('parseCode: valid JavaScript returns a ParseResult', () => {
  const result = parseCode('const x = 1;', 'javascript');
  assert.ok(result);
  assert.equal(result?.language, 'javascript');
  assert.equal(result?.file.type, 'File');
});

test('parseCode: valid TypeScript with type annotation', () => {
  const result = parseCode('const x: number = 1;', 'typescript');
  assert.ok(result);
  assert.equal(result?.language, 'typescript');
});

test('parseCode: JSX in TypeScript', () => {
  const result = parseCode('const el = <div>hello</div>;', 'typescript');
  assert.ok(result);
});

test('parseCode: syntax error returns null (does not throw)', () => {
  const result = parseCode('const x = ;', 'javascript');
  assert.equal(result, null);
});

test('parseCode: empty string returns a ParseResult with empty program', () => {
  const result = parseCode('', 'javascript');
  assert.ok(result);
  assert.equal(result?.file.program.body.length, 0);
});

test('parseCode: unknown language defaults safely (treats as javascript)', () => {
  const result = parseCode('const x = 1;', 'rust' as any);
  assert.ok(result);
});
```

- [ ] **Step 3: Run — expect import failure**

```bash
npm test -- src/utils/ast/__tests__/parser.test.ts
```
Expected: cannot find module `'../parser.js'`.

- [ ] **Step 4: Implement `parser.ts`**

Create `src/utils/ast/parser.ts`:
```ts
import { parse as babelParse } from '@babel/parser';
import type { File } from '@babel/types';

export interface ParseResult {
  file: File;
  language: 'javascript' | 'typescript';
}

/**
 * Parse JS or TS source into a babel AST. Returns null on syntax error.
 * Never throws.
 *
 * - JSX is always enabled (covers React).
 * - TypeScript plugin is enabled when language === 'typescript'.
 * - Common stage-3 syntax (decorators-legacy, class-properties, optional
 *   chaining, nullish coalescing) is enabled to maximize coverage.
 */
export function parseCode(
  code: string,
  language: 'javascript' | 'typescript' = 'javascript'
): ParseResult | null {
  const isTs = language === 'typescript';
  try {
    const file = babelParse(code, {
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      plugins: [
        'jsx',
        isTs ? 'typescript' : 'flow',
        'decorators-legacy',
        'classProperties',
        'dynamicImport',
        'optionalChaining',
        'nullishCoalescingOperator',
      ],
    });
    return { file, language: isTs ? 'typescript' : 'javascript' };
  } catch {
    return null;
  }
}
```

- [ ] **Step 5: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/parser.test.ts
```
Expected: 6 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/utils/ast/parser.ts src/utils/ast/__tests__/parser.test.ts
git rm src/utils/ast/__tests__/_smoke.test.ts
git commit -m "$(cat <<'EOF'
feat(utils/ast): add parser.ts — babel-parser wrapper

parseCode(code, language) returns a ParseResult on success and null on
syntax error. Never throws. Enables jsx + ts + common stage-3 plugins.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `traverse.ts` — generic AST walker

**Files:**
- Create: `src/utils/ast/traverse.ts`
- Create: `src/utils/ast/__tests__/traverse.test.ts`

- [ ] **Step 1: Write failing tests**

Create `src/utils/ast/__tests__/traverse.test.ts`:
```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Node } from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';

test('walk: visits every node in a simple program', () => {
  const ast = parseCode('const x = 1;', 'javascript')!;
  const seen: string[] = [];
  walk(ast.file, (node) => {
    seen.push(node.type);
  });
  // File → Program → VariableDeclaration → VariableDeclarator → Identifier + NumericLiteral
  assert.ok(seen.includes('Program'));
  assert.ok(seen.includes('VariableDeclaration'));
  assert.ok(seen.includes('VariableDeclarator'));
  assert.ok(seen.includes('Identifier'));
  assert.ok(seen.includes('NumericLiteral'));
});

test('walk: visitor returning false skips children', () => {
  const ast = parseCode('const x = { a: 1, b: 2 };', 'javascript')!;
  const seen: string[] = [];
  walk(ast.file, (node) => {
    seen.push(node.type);
    if (node.type === 'ObjectExpression') return false; // skip children
  });
  assert.ok(seen.includes('ObjectExpression'));
  // Object property values should NOT be visited
  assert.equal(seen.filter(n => n === 'ObjectProperty').length, 0);
});

test('walk: parent and ancestors are passed to visitor', () => {
  const ast = parseCode('const x = 1;', 'javascript')!;
  let parentForIdentifier: Node | null | undefined;
  let ancestorsForIdentifier: Node[] | undefined;
  walk(ast.file, (node, parent, ancestors) => {
    if (node.type === 'Identifier' && (node as any).name === 'x') {
      parentForIdentifier = parent;
      ancestorsForIdentifier = ancestors;
    }
  });
  assert.equal(parentForIdentifier?.type, 'VariableDeclarator');
  assert.ok(ancestorsForIdentifier);
  assert.ok(ancestorsForIdentifier!.some(n => n.type === 'VariableDeclaration'));
});

test('walk: handles array children (e.g. function params)', () => {
  const ast = parseCode('function f(a, b, c) {}', 'javascript')!;
  const paramNames: string[] = [];
  walk(ast.file, (node) => {
    if (node.type === 'FunctionDeclaration') {
      for (const p of node.params) {
        if (p.type === 'Identifier') paramNames.push(p.name);
      }
    }
  });
  assert.deepEqual(paramNames, ['a', 'b', 'c']);
});

test('walk: empty program does not throw', () => {
  const ast = parseCode('', 'javascript')!;
  walk(ast.file, () => {}); // no-op visitor
});
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test -- src/utils/ast/__tests__/traverse.test.ts
```

- [ ] **Step 3: Implement `traverse.ts`**

Create `src/utils/ast/traverse.ts`:
```ts
import type { Node, File } from '@babel/types';

export type Visitor = (
  node: Node,
  parent: Node | null,
  ancestors: Node[]
) => boolean | void;

const NODE_KEY_SKIP = new Set(['loc', 'range', 'tokens', 'comments', 'extra']);

/**
 * Walk an AST depth-first. Visits the root and all descendants.
 * If the visitor returns `false`, the node's children are skipped.
 */
export function walk(root: Node, visitor: Visitor): void {
  const ancestors: Node[] = [];

  function visit(node: Node, parent: Node | null) {
    if (!node || typeof node !== 'object' || !(node as any).type) return;
    ancestors.push(node);
    const shouldRecurse = visitor(node, parent, ancestors.slice(0, -1)) !== false;

    if (shouldRecurse) {
      for (const key of Object.keys(node)) {
        if (NODE_KEY_SKIP.has(key)) continue;
        const child = (node as any)[key];
        if (Array.isArray(child)) {
          for (const item of child) {
            if (item && typeof item === 'object' && (item as any).type) {
              visit(item, node);
            }
          }
        } else if (child && typeof child === 'object' && (child as any).type) {
          visit(child, node);
        }
      }
    }
    ancestors.pop();
  }

  visit(root, null);
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/traverse.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/utils/ast/traverse.ts src/utils/ast/__tests__/traverse.test.ts
git commit -m "feat(utils/ast): add traverse.ts — generic AST walker

walk(root, visitor) visits every Node depth-first. Visitor receives
parent and ancestors. Returning false from the visitor skips children.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `sources.ts` — taint source matchers

**Files:**
- Create: `src/utils/ast/sources.ts`
- Create: `src/utils/ast/__tests__/sources.test.ts`

- [ ] **Step 1: Write failing tests**

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import { isUserInputSource } from '../sources.js';

function firstMemberExpression(code: string): t.MemberExpression | null {
  const ast = parseCode(code, 'javascript')!;
  let found: t.MemberExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isMemberExpression(node)) found = node;
  });
  return found;
}

test('isUserInputSource: req.body.x is a source', () => {
  const me = firstMemberExpression('const x = req.body.x;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: req.query.foo is a source', () => {
  const me = firstMemberExpression('const x = req.query.foo;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: req.params.id is a source', () => {
  const me = firstMemberExpression('const x = req.params.id;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: request.body is a source (named export style)', () => {
  const me = firstMemberExpression('const x = request.body;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: ctx.request.body is a source (Koa style)', () => {
  // Outer MemberExpression is ctx.request.body
  const ast = parseCode('const x = ctx.request.body;', 'javascript')!;
  let outerMember: t.MemberExpression | null = null;
  walk(ast.file, (node) => {
    if (t.isVariableDeclarator(node) && t.isMemberExpression(node.init)) {
      outerMember = node.init;
    }
  });
  assert.equal(isUserInputSource(outerMember!), true);
});

test('isUserInputSource: event.body is a source (Lambda style)', () => {
  const me = firstMemberExpression('const x = event.body;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: process.env.X is NOT a source (trusted)', () => {
  const me = firstMemberExpression('const x = process.env.X;')!;
  assert.equal(isUserInputSource(me), false);
});

test('isUserInputSource: process.argv IS a source', () => {
  const me = firstMemberExpression('const x = process.argv;')!;
  assert.equal(isUserInputSource(me), true);
});

test('isUserInputSource: foo.bar is not a source', () => {
  const me = firstMemberExpression('const x = foo.bar;')!;
  assert.equal(isUserInputSource(me), false);
});

test('isUserInputSource: non-MemberExpression returns false', () => {
  assert.equal(isUserInputSource(t.identifier('x')), false);
  assert.equal(isUserInputSource(t.stringLiteral('hi')), false);
});
```

- [ ] **Step 2: Run — expect failures**

- [ ] **Step 3: Implement `sources.ts`**

```ts
import * as t from '@babel/types';

/**
 * Whether `node` represents a user-controlled input source.
 *
 * Recognized patterns (top of expression, in any nesting level the caller
 * passes in):
 *   req.body / req.query / req.params / req.cookies / req.headers / req.url
 *   request.body / request.query / request.params / request.form
 *   ctx.request.body / ctx.request.query / ...
 *   event.body / event.queryStringParameters / event.pathParameters
 *   process.argv
 *
 * Explicitly NOT recognized (trusted):
 *   process.env.*
 */
export function isUserInputSource(node: t.Node): boolean {
  if (t.isMemberExpression(node)) {
    return matchesMember(node);
  }
  return false;
}

const USER_INPUT_FIELDS = new Set([
  'body', 'query', 'params', 'cookies', 'headers', 'url', 'form', 'args',
  'queryStringParameters', 'pathParameters', 'multiValueHeaders',
]);

const TOP_LEVEL_USER_OBJECTS = new Set(['req', 'request', 'event']);

function matchesMember(me: t.MemberExpression): boolean {
  // Walk leftwards down the member chain to find the root identifier
  // and the field accessed *directly* on it.
  let current: t.Node = me;
  while (t.isMemberExpression(current)) {
    const object = current.object;
    const property = current.property;

    if (t.isIdentifier(object) && t.isIdentifier(property)) {
      // Pattern: req.body, req.body.x → object='req', property='body' (and possibly nested member)
      if (TOP_LEVEL_USER_OBJECTS.has(object.name) && USER_INPUT_FIELDS.has(property.name)) {
        return true;
      }
      // Pattern: process.argv → object='process', property='argv'
      if (object.name === 'process' && property.name === 'argv') return true;
      // Pattern: process.env.X (negative — explicitly not a source)
      if (object.name === 'process' && property.name === 'env') return false;
    }

    // Pattern: ctx.request.body — descend through `ctx.request`
    if (t.isMemberExpression(object) && t.isIdentifier(property) && USER_INPUT_FIELDS.has(property.name)) {
      const inner = object;
      if (t.isIdentifier(inner.object) && t.isIdentifier(inner.property)) {
        if (inner.object.name === 'ctx' && inner.property.name === 'request') return true;
      }
    }

    current = current.object;
  }
  return false;
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/sources.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/utils/ast/sources.ts src/utils/ast/__tests__/sources.test.ts
git commit -m "feat(utils/ast): add sources.ts — taint-source matchers

isUserInputSource(node) recognizes req/request/event.* member chains and
process.argv. Explicitly excludes process.env (trusted).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `sinks.ts` — sink definitions and matcher

**Files:**
- Create: `src/utils/ast/sinks.ts`
- Create: `src/utils/ast/__tests__/sinks.test.ts`

- [ ] **Step 1: Write failing tests**

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import {
  SQL_SINKS, COMMAND_SINKS, INNERHTML_SINKS, FS_SINKS, MONGO_SINKS, matchSink,
} from '../sinks.js';

function firstCall(code: string): t.CallExpression | null {
  const ast = parseCode(code, 'javascript')!;
  let found: t.CallExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isCallExpression(node)) found = node;
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

test('FS: fs.chmod with permissive mode is a separate concern, not in FS_SINKS taint sinks', () => {
  // chmod is a permission-only finding, handled directly by the path scanner
  // without taint analysis. Confirming chmod is NOT in FS_SINKS.
  const call = firstCall('fs.chmod(p, 0o777);')!;
  const matched = FS_SINKS.some(s => matchSink(call, s).match);
  assert.equal(matched, false, 'fs.chmod is not a taint sink');
});

test('matchSink: returns argIndex from the SinkDefinition', () => {
  const call = firstCall('db.query("SELECT 1");')!;
  const def = SQL_SINKS[0];
  const m = matchSink(call, def);
  assert.ok(m.match);
  assert.equal(m.argIndex, 0);
});
```

- [ ] **Step 2: Run — expect failures**

- [ ] **Step 3: Implement `sinks.ts`**

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../../types.js';

export type Severity = SecurityIssue['severity'];

export interface SinkDefinition {
  /** Stable identifier surfaced as `SecurityIssue.type`. */
  name: string;
  /** Coarse category for the function-summary record. */
  kind: 'sql' | 'command' | 'innerHTML' | 'fs' | 'mongo';
  /** Predicate over a CallExpression that returns true if this is the sink. */
  matches: (call: t.CallExpression) => boolean;
  /** Which argument index carries the user-controlled input. */
  argIndex: number;
  severity: Severity;
  message: string;
  fix: string;
  owaspCategory?: string;
  cweId?: string;
}

function calleeMethodNameIn(call: t.CallExpression, names: Set<string>): boolean {
  if (!t.isMemberExpression(call.callee)) return false;
  return t.isIdentifier(call.callee.property) && names.has(call.callee.property.name);
}

function calleeIdentifierIn(call: t.CallExpression, names: Set<string>): boolean {
  return t.isIdentifier(call.callee) && names.has(call.callee.name);
}

const SQL_METHODS = new Set(['query', 'execute', 'sql', 'raw']);
const COMMAND_METHODS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);
const COMMAND_IDENTS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync', 'system', 'popen']);
const MONGO_METHODS = new Set(['find', 'findOne', 'updateOne', 'deleteOne', 'updateMany', 'deleteMany']);
const FS_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'unlink', 'unlinkSync', 'rmdir', 'rmdirSync', 'rm', 'rmSync',
  'createReadStream', 'createWriteStream', 'readdir', 'readdirSync',
]);

export const SQL_SINKS: SinkDefinition[] = [
  {
    name: 'SQL query with user input',
    kind: 'sql',
    matches: (call) => calleeMethodNameIn(call, SQL_METHODS),
    argIndex: 0,
    severity: 'high',
    message: '사용자 입력이 SQL 쿼리에 직접 들어가고 있습니다.',
    fix: 'Prepared Statement 또는 Parameterized Query를 사용하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-89',
  },
];

export const COMMAND_SINKS: SinkDefinition[] = [
  {
    name: 'Command Injection',
    kind: 'command',
    matches: (call) =>
      calleeIdentifierIn(call, COMMAND_IDENTS) || calleeMethodNameIn(call, COMMAND_METHODS),
    argIndex: 0,
    severity: 'critical',
    message: '사용자 입력이 시스템 명령어 호출에 흘러들어갑니다. Command Injection!',
    fix: '사용자 입력을 시스템 명령에 사용하지 마세요. 꼭 필요하면 화이트리스트 검증을 하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-78',
  },
];

export const MONGO_SINKS: SinkDefinition[] = [
  {
    name: 'MongoDB Injection',
    kind: 'mongo',
    matches: (call) => calleeMethodNameIn(call, MONGO_METHODS),
    argIndex: 0,
    severity: 'high',
    message: '사용자 입력이 MongoDB 쿼리 객체에 들어갑니다.',
    fix: 'mongo-sanitize 또는 스키마 검증으로 입력을 제한하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-943',
  },
];

export const FS_SINKS: SinkDefinition[] = [
  {
    name: 'Path Traversal Risk',
    kind: 'fs',
    matches: (call) => calleeMethodNameIn(call, FS_METHODS),
    argIndex: 0,
    severity: 'critical',
    message: '사용자 입력으로 파일 경로를 구성하고 있습니다.',
    fix: 'path.basename()으로 정규화하거나 허용 디렉토리를 화이트리스트로 제한하세요.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cweId: 'CWE-22',
  },
];

/** Definitions for innerHTML-style XSS. These match AssignmentExpression nodes
 *  (NOT CallExpression). The xss scanner uses matchInnerHtmlAssignment, not matchSink. */
export const INNERHTML_SINKS: SinkDefinition[] = [
  {
    name: 'innerHTML with non-literal',
    kind: 'innerHTML',
    matches: () => false, // unused for CallExpression matching
    argIndex: -1,
    severity: 'high',
    message: 'innerHTML에 문자열 리터럴이 아닌 값을 할당하고 있습니다. XSS 위험.',
    fix: 'textContent를 사용하거나 DOMPurify로 sanitize하세요.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-79',
  },
];

export interface SinkMatchResult {
  match: boolean;
  argIndex: number;
}

export function matchSink(call: t.CallExpression, def: SinkDefinition): SinkMatchResult {
  if (!def.matches(call)) return { match: false, argIndex: -1 };
  return { match: true, argIndex: def.argIndex };
}

/**
 * Match `node.innerHTML = rhs` style assignments. Returns the RHS expression
 * if matched, else null. Used by the xss scanner.
 */
export function matchInnerHtmlAssignment(
  node: t.AssignmentExpression
): t.Expression | null {
  if (node.operator !== '=') return null;
  if (!t.isMemberExpression(node.left)) return null;
  if (!t.isIdentifier(node.left.property)) return null;
  if (node.left.property.name !== 'innerHTML' && node.left.property.name !== 'outerHTML') return null;
  return node.right as t.Expression;
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/sinks.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/utils/ast/sinks.ts src/utils/ast/__tests__/sinks.test.ts
git commit -m "feat(utils/ast): add sinks.ts — sink definitions and matcher

SQL_SINKS, COMMAND_SINKS, MONGO_SINKS, FS_SINKS, INNERHTML_SINKS.
matchSink(call, def) for CallExpression sinks; matchInnerHtmlAssignment
for the assignment-style innerHTML sink.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `location.ts` — node to SecurityIssue converter

**Files:**
- Create: `src/utils/ast/location.ts`
- Create: `src/utils/ast/__tests__/location.test.ts`

- [ ] **Step 1: Write failing tests**

```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as t from '@babel/types';
import { parseCode } from '../parser.js';
import { walk } from '../traverse.js';
import { SQL_SINKS } from '../sinks.js';
import { toIssue } from '../location.js';

function firstCall(code: string): t.CallExpression {
  const ast = parseCode(code, 'javascript')!;
  let found: t.CallExpression | null = null;
  walk(ast.file, (node) => {
    if (!found && t.isCallExpression(node)) found = node;
  });
  return found!;
}

test('toIssue: returns SecurityIssue with line from node.loc', () => {
  const code = 'line1\nline2\ndb.query("SELECT 1");\nline4';
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.equal(issue.type, SQL_SINKS[0].name);
  assert.equal(issue.line, 3);
  assert.equal(issue.severity, 'high');
  assert.equal(issue.owaspCategory, 'A03:2021 – Injection');
  assert.equal(issue.cweId, 'CWE-89');
});

test('toIssue: match field contains the source snippet', () => {
  const code = 'db.query("SELECT 1");';
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.ok(issue.match);
  assert.ok(issue.match!.includes('db.query'));
});

test('toIssue: snippet is truncated to a sensible length', () => {
  const longArg = '"' + 'A'.repeat(200) + '"';
  const code = `db.query(${longArg});`;
  const call = firstCall(code);
  const issue = toIssue(call, SQL_SINKS[0], code);
  assert.ok(issue.match!.length <= 120);
});

test('toIssue: node without loc still returns an issue (line 0 fallback)', () => {
  // Synthesize a call node without loc.
  const callee = t.memberExpression(t.identifier('db'), t.identifier('query'));
  const call = t.callExpression(callee, [t.stringLiteral('x')]);
  // No loc attached.
  const issue = toIssue(call, SQL_SINKS[0], '');
  assert.equal(issue.type, SQL_SINKS[0].name);
  assert.equal(issue.line, 0);
});
```

- [ ] **Step 2: Run — expect failures**

- [ ] **Step 3: Implement `location.ts`**

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../../types.js';
import type { SinkDefinition } from './sinks.js';

const SNIPPET_MAX = 120;

/**
 * Convert an AST node + matching SinkDefinition into a SecurityIssue.
 *
 * The returned issue uses node.loc.start.line (1-based) for `line`. If the
 * node has no loc (synthesized nodes), line falls back to 0.
 */
export function toIssue(node: t.Node, def: SinkDefinition, code: string): SecurityIssue {
  const line = node.loc?.start.line ?? 0;
  const snippet = extractSnippet(node, code).slice(0, SNIPPET_MAX);
  return {
    type: def.name,
    severity: def.severity,
    message: def.message,
    fix: def.fix,
    line,
    match: snippet,
    owaspCategory: def.owaspCategory,
    cweId: def.cweId,
  };
}

function extractSnippet(node: t.Node, code: string): string {
  if (!node.loc) return '';
  const start = node.loc.start;
  const end = node.loc.end;
  const lines = code.split('\n');
  if (start.line === end.line) {
    const line = lines[start.line - 1] ?? '';
    return line.slice(start.column, end.column).trim();
  }
  // Multi-line: return the start line trimmed.
  return (lines[start.line - 1] ?? '').trim();
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/location.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/utils/ast/location.ts src/utils/ast/__tests__/location.test.ts
git commit -m "feat(utils/ast): add location.ts — AST node to SecurityIssue converter

toIssue(node, sinkDef, code) extracts 1-based line, severity, OWASP/CWE
metadata, and a truncated snippet from node.loc.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7a: `taint.ts` — top-level variable taint (T-1..T-5)

**Files:**
- Create: `src/utils/ast/taint.ts` (partial — only top-level taint in this task)
- Create: `src/utils/ast/__tests__/taint.test.ts` (T-1..T-5 only; T-6..T-10 added in Task 7b)

- [ ] **Step 1: Write failing tests (T-1..T-5)**

Create `src/utils/ast/__tests__/taint.test.ts`:
```ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCode } from '../parser.js';
import { analyzeTaint } from '../taint.js';

test('T-1: const a = req.body.x → taintedVars includes a', () => {
  const ast = parseCode('const a = req.body.x;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
});

test('T-2: multi-hop two-step', () => {
  const ast = parseCode('const a = req.body.x; const b = a;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
  assert.ok(state.taintedVars.has('b'));
});

test('T-3: transitive three-step', () => {
  const ast = parseCode(
    'const a = req.body.x; const b = a; const c = b;',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  assert.ok(state.taintedVars.has('a'));
  assert.ok(state.taintedVars.has('b'));
  assert.ok(state.taintedVars.has('c'));
});

test('T-4: process.env is trusted (a stays clean)', () => {
  const ast = parseCode('const a = process.env.X;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.equal(state.taintedVars.has('a'), false);
});

test('T-5: literal RHS does not taint', () => {
  const ast = parseCode('const a = "literal"; const b = a;', 'javascript')!;
  const state = analyzeTaint(ast);
  assert.equal(state.taintedVars.has('a'), false);
  assert.equal(state.taintedVars.has('b'), false);
});
```

- [ ] **Step 2: Run — expect import failure**

```bash
npm test -- src/utils/ast/__tests__/taint.test.ts
```

- [ ] **Step 3: Implement `taint.ts` (top-level taint only)**

Create `src/utils/ast/taint.ts`:
```ts
import * as t from '@babel/types';
import type { ParseResult } from './parser.js';
import { walk } from './traverse.js';
import { isUserInputSource } from './sources.js';

export type SinkKind = 'sql' | 'command' | 'innerHTML' | 'fs' | 'mongo';

export interface SinkFlow {
  sinkKind: SinkKind;
  callNode: t.CallExpression;
}

export interface FunctionSummary {
  /** Parameter names in declaration order. */
  paramOrder: string[];
  /** paramName → list of sink-reaches found in this function's body. */
  paramFlows: Map<string, SinkFlow[]>;
}

export interface TaintState {
  /** Top-level variables transitively assigned from a user-input source. */
  taintedVars: Set<string>;
  /** Function name → summary of which params reach which sinks. */
  functionSummaries: Map<string, FunctionSummary>;
}

/**
 * Build a TaintState for the given parsed file. Runs:
 *   - Pre-pass: fixed-point top-level variable taint.
 *   - Main-pass: function summaries (filled in Task 7b — empty for now).
 */
export function analyzeTaint(parsed: ParseResult): TaintState {
  const state: TaintState = {
    taintedVars: new Set(),
    functionSummaries: new Map(),
  };

  // Pre-pass: fixed-point iteration.
  let changed = true;
  let iterations = 0;
  while (changed && iterations < 50) {
    changed = false;
    iterations++;
    walk(parsed.file, (node, _parent, ancestors) => {
      // Skip nodes inside function bodies (function summaries handle those).
      if (isInsideFunctionBody(ancestors)) return;

      if (t.isVariableDeclarator(node)) {
        const id = node.id;
        const init = node.init;
        if (t.isIdentifier(id) && init && isTaintedExpression(init, state)) {
          if (!state.taintedVars.has(id.name)) {
            state.taintedVars.add(id.name);
            changed = true;
          }
        }
      } else if (t.isAssignmentExpression(node) && node.operator === '=') {
        if (t.isIdentifier(node.left) && isTaintedExpression(node.right, state)) {
          if (!state.taintedVars.has(node.left.name)) {
            state.taintedVars.add(node.left.name);
            changed = true;
          }
        }
      }
    });
  }

  return state;
}

/**
 * Whether `node` (an expression) evaluates to a tainted value, given the
 * current state. Used both internally during analysis and externally by
 * the scanners.
 */
export function isTainted(node: t.Node, state: TaintState): boolean {
  return isTaintedExpression(node, state);
}

function isTaintedExpression(node: t.Node, state: TaintState): boolean {
  if (!node) return false;

  if (isUserInputSource(node)) return true;

  if (t.isIdentifier(node)) {
    return state.taintedVars.has(node.name);
  }

  if (t.isTemplateLiteral(node)) {
    return node.expressions.some((e) => isTaintedExpression(e, state));
  }

  if (t.isBinaryExpression(node) && node.operator === '+') {
    return isTaintedExpression(node.left, state) || isTaintedExpression(node.right, state);
  }

  if (t.isMemberExpression(node)) {
    // Already handled by isUserInputSource for known patterns. For unknown
    // member chains, taint propagates from the object.
    return isTaintedExpression(node.object, state);
  }

  if (t.isCallExpression(node)) {
    // Conservative: if any argument is tainted, the call result is tainted.
    return node.arguments.some((a) => isTaintedExpression(a as t.Node, state));
  }

  return false;
}

function isInsideFunctionBody(ancestors: t.Node[]): boolean {
  return ancestors.some(
    (a) =>
      t.isFunctionDeclaration(a) ||
      t.isFunctionExpression(a) ||
      t.isArrowFunctionExpression(a) ||
      t.isObjectMethod(a) ||
      t.isClassMethod(a)
  );
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/utils/ast/__tests__/taint.test.ts
```
Expected: 5 pass (T-1..T-5).

- [ ] **Step 5: Commit**

```bash
git add src/utils/ast/taint.ts src/utils/ast/__tests__/taint.test.ts
git commit -m "feat(utils/ast): add taint.ts top-level variable taint (T-1..T-5)

Fixed-point iteration over top-level VariableDeclarator and
AssignmentExpression nodes. Recognizes user-input sources via sources.ts;
treats process.env as trusted. Function summaries added in Task 7b.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7b: `taint.ts` — function summaries (T-6..T-10)

**Files:**
- Modify: `src/utils/ast/taint.ts`
- Modify: `src/utils/ast/__tests__/taint.test.ts`

- [ ] **Step 1: Append failing T-6..T-10 tests**

Append to `src/utils/ast/__tests__/taint.test.ts`:
```ts
test('T-6: function h(input) with SQL sink → paramFlows.input has sql sink', () => {
  const ast = parseCode(
    'function h(input) { db.query(`SELECT * FROM u WHERE id = ${input}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h');
  assert.ok(summary, 'expected summary for h');
  const flows = summary!.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});

test('T-7: only the referenced param shows a flow', () => {
  const ast = parseCode(
    'function h(a, b) { db.query(`SELECT * FROM u WHERE id = ${b}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const bFlows = summary.paramFlows.get('b') ?? [];
  const aFlows = summary.paramFlows.get('a') ?? [];
  assert.ok(bFlows.some((f) => f.sinkKind === 'sql'));
  assert.equal(aFlows.length, 0);
});

test('T-8: function-body multi-hop reaches sink', () => {
  const ast = parseCode(
    'function h(input) { const x = input; db.query(`... ${x}`); }',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  const flows = summary.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});

test('T-9: empty function body has empty paramFlows', () => {
  const ast = parseCode('function h(a, b) {}', 'javascript')!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h')!;
  assert.equal(summary.paramFlows.get('a')?.length ?? 0, 0);
  assert.equal(summary.paramFlows.get('b')?.length ?? 0, 0);
});

test('T-10: arrow function assigned to variable is recognized', () => {
  const ast = parseCode(
    'const h = (input) => db.query(`... ${input}`);',
    'javascript'
  )!;
  const state = analyzeTaint(ast);
  const summary = state.functionSummaries.get('h');
  assert.ok(summary, 'expected summary for h');
  const flows = summary!.paramFlows.get('input') ?? [];
  assert.ok(flows.some((f) => f.sinkKind === 'sql'));
});
```

- [ ] **Step 2: Run — expect 5 new failures**

```bash
npm test -- src/utils/ast/__tests__/taint.test.ts
```

- [ ] **Step 3: Extend `analyzeTaint` to fill `functionSummaries`**

Add the following helpers and main-pass logic to `src/utils/ast/taint.ts`. Append after the existing exports (keep the pre-pass intact):

```ts
import { SQL_SINKS, COMMAND_SINKS, MONGO_SINKS, FS_SINKS, INNERHTML_SINKS, matchSink, matchInnerHtmlAssignment } from './sinks.js';

// Extend analyzeTaint by adding the main-pass at the end of its body, just
// before `return state;`. Replace the original function body's final line
// with:
//
//   buildFunctionSummaries(parsed, state);
//   return state;
//
// Add the helper functions below.

function buildFunctionSummaries(parsed: ParseResult, state: TaintState): void {
  walk(parsed.file, (node, parent) => {
    if (t.isFunctionDeclaration(node)) {
      const name = node.id?.name;
      if (!name) return;
      state.functionSummaries.set(name, analyzeFunctionBody(node));
    } else if (
      t.isVariableDeclarator(node) &&
      t.isIdentifier(node.id) &&
      (t.isFunctionExpression(node.init) || t.isArrowFunctionExpression(node.init))
    ) {
      state.functionSummaries.set(node.id.name, analyzeFunctionBody(node.init));
    }
  });
}

function analyzeFunctionBody(
  fn: t.FunctionDeclaration | t.FunctionExpression | t.ArrowFunctionExpression
): FunctionSummary {
  const paramOrder: string[] = [];
  const paramFlows = new Map<string, SinkFlow[]>();

  for (const p of fn.params) {
    if (t.isIdentifier(p)) {
      paramOrder.push(p.name);
      paramFlows.set(p.name, []);
    } else {
      // Destructuring / rest params: not modeled in PR 2.
      paramOrder.push('');
    }
  }

  // Local taint propagation inside the function body.
  const localTainted = new Set(paramOrder.filter(Boolean));
  const body = fn.body;
  if (!body || (!t.isBlockStatement(body) && !t.isExpression(body))) {
    return { paramOrder, paramFlows };
  }

  // Pre-pass: multi-hop within the body.
  let changed = true;
  let iterations = 0;
  while (changed && iterations < 50) {
    changed = false;
    iterations++;
    walk(body as t.Node, (node) => {
      if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
        if (expressionReferencesLocal(node.init, localTainted)) {
          if (!localTainted.has(node.id.name)) {
            localTainted.add(node.id.name);
            changed = true;
          }
        }
      } else if (
        t.isAssignmentExpression(node) &&
        node.operator === '=' &&
        t.isIdentifier(node.left)
      ) {
        if (expressionReferencesLocal(node.right, localTainted)) {
          if (!localTainted.has(node.left.name)) {
            localTainted.add(node.left.name);
            changed = true;
          }
        }
      }
    });
  }

  // Main pass: find sink calls referencing parameters (directly or via localTainted).
  walk(body as t.Node, (node) => {
    if (!t.isCallExpression(node)) return;
    const sinkKind = identifySinkKind(node);
    if (!sinkKind) return;
    const argIdx = 0; // current sink registry uses index 0 for all CallExpression sinks
    const arg = node.arguments[argIdx];
    if (!arg) return;
    for (const paramName of paramOrder) {
      if (!paramName) continue;
      if (expressionReferencesParamOrAlias(arg as t.Node, paramName, localTainted)) {
        const flows = paramFlows.get(paramName)!;
        flows.push({ sinkKind, callNode: node });
      }
    }
  });

  return { paramOrder, paramFlows };
}

function expressionReferencesLocal(node: t.Node, localTainted: Set<string>): boolean {
  let found = false;
  walk(node, (n) => {
    if (found) return false;
    if (t.isIdentifier(n) && localTainted.has(n.name)) found = true;
  });
  return found;
}

function expressionReferencesParamOrAlias(
  node: t.Node,
  paramName: string,
  localTainted: Set<string>
): boolean {
  // Does the expression reference paramName directly, or any local var that
  // was tainted by paramName?
  let found = false;
  walk(node, (n) => {
    if (found) return false;
    if (t.isIdentifier(n) && (n.name === paramName || localTainted.has(n.name))) {
      // For 'localTainted' aliases, we already widened the set in the local pre-pass.
      // To check that the alias traces back specifically to THIS param, we'd need
      // per-param coloring; for PR 2 we accept the conservative "any local tainted".
      found = true;
    }
  });
  return found;
}

function identifySinkKind(call: t.CallExpression): SinkKind | null {
  for (const def of SQL_SINKS) if (matchSink(call, def).match) return def.kind;
  for (const def of COMMAND_SINKS) if (matchSink(call, def).match) return def.kind;
  for (const def of MONGO_SINKS) if (matchSink(call, def).match) return def.kind;
  for (const def of FS_SINKS) if (matchSink(call, def).match) return def.kind;
  return null;
}
```

Then change the bottom of `analyzeTaint` to:
```ts
  buildFunctionSummaries(parsed, state);
  return state;
}
```

- [ ] **Step 4: Run — expect all 10 pass**

```bash
npm test -- src/utils/ast/__tests__/taint.test.ts
```

**Caveat for T-7:** the conservative `expressionReferencesParamOrAlias` may register a flow on parameter `a` if any local var derived from `a` reaches the sink. In the literal T-7 source (`function h(a, b) { db.query(\`... ${b}\`); }`), `a` is never aliased to any local, so `localTainted` contains only `b`. The visitor checks `n.name === paramName ('a')` and `localTainted.has(n.name)`. The arg is `${b}` which is `b` — `n.name === 'a'` is false, `localTainted.has('b')` is true. The current implementation would incorrectly mark a flow on `a` as well because `localTainted.has('b')` returns true regardless of which param we're checking.

To fix: track per-param taint coloring. Introduce `paramTainted: Map<paramName, Set<localVarName>>` instead of a single `localTainted` set.

Revised local analysis (replace the loop above):
```ts
  // Per-param coloring.
  const paramTainted = new Map<string, Set<string>>();
  for (const p of paramOrder.filter(Boolean)) {
    paramTainted.set(p, new Set([p]));
  }

  // Pre-pass per param.
  for (const [paramName, local] of paramTainted) {
    let changed = true;
    let iterations = 0;
    while (changed && iterations < 50) {
      changed = false;
      iterations++;
      walk(body as t.Node, (node) => {
        if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
          if (expressionReferencesLocal(node.init, local)) {
            if (!local.has(node.id.name)) {
              local.add(node.id.name);
              changed = true;
            }
          }
        } else if (
          t.isAssignmentExpression(node) &&
          node.operator === '=' &&
          t.isIdentifier(node.left)
        ) {
          if (expressionReferencesLocal(node.right, local)) {
            if (!local.has(node.left.name)) {
              local.add(node.left.name);
              changed = true;
            }
          }
        }
      });
    }
  }

  // Main pass: per param, find sinks referencing its color.
  walk(body as t.Node, (node) => {
    if (!t.isCallExpression(node)) return;
    const sinkKind = identifySinkKind(node);
    if (!sinkKind) return;
    const arg = node.arguments[0];
    if (!arg) return;
    for (const [paramName, local] of paramTainted) {
      if (expressionReferencesLocal(arg as t.Node, local)) {
        const flows = paramFlows.get(paramName)!;
        flows.push({ sinkKind, callNode: node });
      }
    }
  });
```

Then `expressionReferencesParamOrAlias` is no longer needed; remove it.

- [ ] **Step 5: Run again — T-7 should now pass**

```bash
npm test -- src/utils/ast/__tests__/taint.test.ts
```
Expected: all 10 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/utils/ast/taint.ts src/utils/ast/__tests__/taint.test.ts
git commit -m "feat(utils/ast): add function summaries with per-param coloring

T-6..T-10. Each function gets a FunctionSummary mapping each parameter to
the sinks reachable from it through the function body. Per-param taint
coloring avoids the false flow that would occur with a single shared
local-tainted set (T-7).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `index.ts` — barrel export

**Files:**
- Create: `src/utils/ast/index.ts`

- [ ] **Step 1: Create the barrel**

```ts
export { parseCode } from './parser.js';
export type { ParseResult } from './parser.js';

export { walk } from './traverse.js';
export type { Visitor } from './traverse.js';

export { isUserInputSource } from './sources.js';

export {
  SQL_SINKS, COMMAND_SINKS, MONGO_SINKS, FS_SINKS, INNERHTML_SINKS,
  matchSink, matchInnerHtmlAssignment,
} from './sinks.js';
export type { SinkDefinition, SinkMatchResult } from './sinks.js';

export { analyzeTaint, isTainted } from './taint.js';
export type { TaintState, FunctionSummary, SinkFlow, SinkKind } from './taint.js';

export { toIssue } from './location.js';
```

- [ ] **Step 2: Verify build and tests**

```bash
npm run build && npm test
```
Expected: clean build, all tests pass (5+10 from taint + smaller test files from parser/traverse/sources/sinks/location).

- [ ] **Step 3: Commit**

```bash
git add src/utils/ast/index.ts
git commit -m "feat(utils/ast): add barrel export

src/utils/ast/index.ts re-exports the public API of the AST utility
module: parser, traverse, sources, sinks, taint, location.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Refactor `injection.ts` (R-15, R-16, R-22, R-23)

**Files:**
- Modify: `src/scanners/injection.ts`
- Modify: `src/scanners/__tests__/injection.test.ts`

- [ ] **Step 1: Append failing tests to `src/scanners/__tests__/injection.test.ts`**

```ts
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
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test -- src/scanners/__tests__/injection.test.ts
```

- [ ] **Step 3: Refactor `src/scanners/injection.ts`**

Read the current file. It exports `scanInjection(code, language)`. Replace its body with the routing shape below, and **extract** the entire current PR 1 implementation into a new local function `scanInjectionRegex(code, lang)`.

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode,
  walk,
  analyzeTaint,
  isTainted,
  matchSink,
  SQL_SINKS,
  COMMAND_SINKS,
  MONGO_SINKS,
  toIssue,
  type ParseResult,
} from '../utils/ast/index.js';
import { Language } from '../utils/source-helpers.js';

export function scanInjection(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) {
      return scanInjectionAST(code, parsed);
    }
  }
  return scanInjectionRegex(code, lang);
}

function scanInjectionAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const taint = analyzeTaint(parsed);
  const issues: SecurityIssue[] = [];
  const sinks = [...SQL_SINKS, ...COMMAND_SINKS, ...MONGO_SINKS];

  walk(parsed.file, (node) => {
    if (!t.isCallExpression(node)) return;

    // 1. Direct sink.
    for (const def of sinks) {
      const m = matchSink(node, def);
      if (!m.match) continue;
      const arg = node.arguments[m.argIndex];
      if (arg && isTainted(arg as t.Node, taint)) {
        issues.push(toIssue(node, def, code));
        return;
      }
    }

    // 2. Transitive sink via function summary.
    const calleeName = resolveCalleeName(node);
    if (!calleeName) return;
    const summary = taint.functionSummaries.get(calleeName);
    if (!summary) return;
    for (let i = 0; i < node.arguments.length; i++) {
      const paramName = summary.paramOrder[i];
      if (!paramName) continue;
      const flows = summary.paramFlows.get(paramName) ?? [];
      if (flows.length === 0) continue;
      if (isTainted(node.arguments[i] as t.Node, taint)) {
        const flowKinds = new Set(flows.map((f) => f.sinkKind));
        const def = sinks.find((d) => flowKinds.has(d.kind));
        if (def) {
          issues.push(toIssue(node, def, code));
          return;
        }
      }
    }
  });

  return issues;
}

function resolveCalleeName(call: t.CallExpression): string | null {
  if (t.isIdentifier(call.callee)) return call.callee.name;
  if (t.isMemberExpression(call.callee) && t.isIdentifier(call.callee.property)) {
    return call.callee.property.name;
  }
  return null;
}

function scanInjectionRegex(code: string, lang: Language): SecurityIssue[] {
  // ── PASTE the existing PR 1 scanInjection body here, replacing the local
  //    `language` variable with the `lang` parameter. Keep STATIC_PATTERNS,
  //    TAINT_AWARE_PATTERNS, the compile loop, and the match loop unchanged. ──
}
```

> The previous `scanInjection` function began with `const lang = language as Language;`. Lift the body starting from that line into `scanInjectionRegex`, renaming the implicit `lang` to a parameter.

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/scanners/__tests__/injection.test.ts
```
Expected: 4 new tests pass, plus all PR-1 tests in this file remain green.

If R-22 fails, the cause is that `isTaintedExpression` propagates taint through CallExpression conservatively. Edit `src/utils/ast/taint.ts` to remove the CallExpression branch from `isTaintedExpression`:
```ts
// Remove this block:
//   if (t.isCallExpression(node)) {
//     return node.arguments.some(...);
//   }
```
Re-run. T-1..T-10 should still pass; R-22 should now pass.

- [ ] **Step 5: Full suite**

```bash
npm test
```

- [ ] **Step 6: Commit**

```bash
git add src/scanners/injection.ts src/scanners/__tests__/injection.test.ts src/utils/ast/taint.ts
git commit -m "feat(scanners/injection): AST path for JS/TS, regex fallback for other langs

R-15 (function-param taint) and R-16 (multi-hop chain) now detected.
R-22 (return-value taint) pinned as non-goal. R-23 graceful degrade on
parse failure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Refactor `xss.ts` (R-17, R-18, R-24)

**Files:**
- Modify: `src/scanners/xss.ts`
- Modify: `src/scanners/__tests__/xss.test.ts`

- [ ] **Step 1: Append tests**

```ts
test('R-17: literal HTML on innerHTML is NOT flagged (PR 2 fixes PR 1 limitation)', () => {
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

test('R-24: Python code-eval input uses regex fallback', () => {
  const code = 'result = eval(user_input)';
  const issues = scanXss(code, 'python');
  assert.ok(issues.length >= 1);
});
```

Also remove the PR 1 "acknowledged limitation" comment from the literal-HTML test if present in the file.

- [ ] **Step 2: Run — expect R-17 failure**

```bash
npm test -- src/scanners/__tests__/xss.test.ts
```

- [ ] **Step 3: Refactor `src/scanners/xss.ts`**

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode, walk,
  matchInnerHtmlAssignment, INNERHTML_SINKS,
  toIssue,
  type ParseResult,
} from '../utils/ast/index.js';
import { Language } from '../utils/source-helpers.js';

export function scanXss(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) return scanXssAST(code, parsed);
  }
  return scanXssRegex(code, lang);
}

function scanXssAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const issues: SecurityIssue[] = [];
  const innerHtmlDef = INNERHTML_SINKS[0];

  walk(parsed.file, (node) => {
    if (!t.isAssignmentExpression(node)) return;
    const rhs = matchInnerHtmlAssignment(node);
    if (!rhs) return;
    if (t.isStringLiteral(rhs)) return;
    if (t.isTemplateLiteral(rhs) && rhs.expressions.length === 0) return;
    issues.push(toIssue(node, innerHtmlDef, code));
  });

  // Other XSS patterns continue via the regex path; dedupe by (type, line).
  const regexFindings = scanXssRegex(code, parsed.language);
  for (const r of regexFindings) {
    if (r.type.toLowerCase().includes('innerhtml')) continue;
    if (issues.some((i) => i.type === r.type && i.line === r.line)) continue;
    issues.push(r);
  }

  return issues;
}

function scanXssRegex(code: string, lang: Language): SecurityIssue[] {
  // ── PASTE the existing PR 1 scanXss body here, accepting `lang` as the
  //    Language parameter. ──
}
```

- [ ] **Step 4: Run — expect pass**

```bash
npm test -- src/scanners/__tests__/xss.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/scanners/xss.ts src/scanners/__tests__/xss.test.ts
git commit -m "feat(scanners/xss): AST path resolves innerHTML literal limitation (R-17)

AST detects innerHTML assignment with non-literal RHS. Literal HTML on
the RHS is correctly skipped. Other XSS patterns continue via the regex
path, deduplicated by (type, line).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Refactor `crypto.ts` (R-20)

**Files:**
- Modify: `src/scanners/crypto.ts`
- Modify: `src/scanners/__tests__/crypto.test.ts`

The only AST-relevant pattern in crypto is `password = <tainted>`. The other crypto patterns (MD5, weak random, hardcoded keys, ECB, DES, TLS, etc.) are non-taint findings that the regex path handles fine. So the AST path checks just the password-assignment case; everything else routes back through the regex path.

- [ ] **Step 1: Append test**

```ts
test('R-20: crypto multi-hop password storage is flagged', () => {
  const code = `
    const pw = req.body.password;
    const sanitized = pw;
    user.password = sanitized;
  `;
  const issues = scanCrypto(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Plain Password Storage'));
});
```

- [ ] **Step 2: Run — expect failure**

```bash
npm test -- src/scanners/__tests__/crypto.test.ts
```

- [ ] **Step 3: Refactor `src/scanners/crypto.ts`**

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode, walk,
  analyzeTaint, isTainted,
  toIssue,
  type ParseResult,
  type SinkDefinition,
} from '../utils/ast/index.js';
import { Language } from '../utils/source-helpers.js';

const PLAIN_PASSWORD_SINK: SinkDefinition = {
  name: 'Plain Password Storage',
  kind: 'sql', // placeholder; not used in match callback
  matches: () => false,
  argIndex: -1,
  severity: 'high',
  message: '비밀번호를 해싱 없이 저장하려는 것 같습니다.',
  fix: 'bcrypt.hash() 또는 argon2로 해싱한 후 저장하세요.',
  owaspCategory: 'A02:2021 – Cryptographic Failures',
  cweId: 'CWE-256',
};

export function scanCrypto(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) return scanCryptoAST(code, parsed);
  }
  return scanCryptoRegex(code, lang);
}

function scanCryptoAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const taint = analyzeTaint(parsed);
  const issues: SecurityIssue[] = [];

  walk(parsed.file, (node) => {
    // Match: <something>.password = rhs  OR  password = rhs
    if (!t.isAssignmentExpression(node) || node.operator !== '=') return;
    let isPasswordLhs = false;
    if (t.isMemberExpression(node.left) && t.isIdentifier(node.left.property) && node.left.property.name === 'password') {
      isPasswordLhs = true;
    } else if (t.isIdentifier(node.left) && node.left.name === 'password') {
      isPasswordLhs = true;
    }
    if (!isPasswordLhs) return;
    if (isTainted(node.right as t.Node, taint)) {
      issues.push(toIssue(node, PLAIN_PASSWORD_SINK, code));
    }
  });

  // Other crypto findings (MD5, weak RNG, etc.) come from the regex path.
  const regexFindings = scanCryptoRegex(code, parsed.language);
  for (const r of regexFindings) {
    if (r.type === PLAIN_PASSWORD_SINK.name) continue;
    if (issues.some((i) => i.type === r.type && i.line === r.line)) continue;
    issues.push(r);
  }

  return issues;
}

function scanCryptoRegex(code: string, lang: Language): SecurityIssue[] {
  // ── PASTE the existing PR 1 scanCrypto body here. ──
}
```

- [ ] **Step 4: Run + commit**

```bash
npm test -- src/scanners/__tests__/crypto.test.ts && npm test
git add src/scanners/crypto.ts src/scanners/__tests__/crypto.test.ts
git commit -m "feat(scanners/crypto): AST path detects multi-hop password storage

R-20. Other crypto findings (weak hash, hardcoded keys, TLS, etc.)
continue via the regex path, deduplicated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Refactor `auth.ts` (R-19)

**Files:**
- Modify: `src/scanners/auth.ts`
- Modify: `src/scanners/__tests__/auth.test.ts`

AST resolves the PR 1 limitation where the CORS regex couldn't see the header name as a function argument.

- [ ] **Step 1: Append test**

```ts
test('R-19: CORS via setHeader is detected (PR 2 fixes PR 1 limitation)', () => {
  const code = `res.setHeader('Access-Control-Allow-Origin', '*');`;
  const issues = scanAuth(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'CORS Allow All Origins'));
});
```

Remove the PR 1 limitation comment from the auth.test.ts file if present.

- [ ] **Step 2: Run — expect failure**

- [ ] **Step 3: Refactor `src/scanners/auth.ts`**

```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode, walk,
  toIssue,
  type ParseResult,
  type SinkDefinition,
} from '../utils/ast/index.js';
import { Language } from '../utils/source-helpers.js';

const CORS_WILDCARD: SinkDefinition = {
  name: 'CORS Allow All Origins',
  kind: 'sql',
  matches: () => false,
  argIndex: -1,
  severity: 'high',
  message: 'CORS Access-Control-Allow-Origin이 와일드카드(*)로 설정되어 있습니다.',
  fix: '허용할 origin을 명시적으로 화이트리스트로 지정하세요.',
  owaspCategory: 'A05:2021 – Security Misconfiguration',
  cweId: 'CWE-942',
};

export function scanAuth(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) return scanAuthAST(code, parsed);
  }
  return scanAuthRegex(code, lang);
}

function scanAuthAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const issues: SecurityIssue[] = [];

  walk(parsed.file, (node) => {
    if (!t.isCallExpression(node)) return;
    if (!t.isMemberExpression(node.callee)) return;
    if (!t.isIdentifier(node.callee.property)) return;
    if (node.callee.property.name !== 'setHeader' && node.callee.property.name !== 'header') return;
    // setHeader('Access-Control-Allow-Origin', '*')
    const [first, second] = node.arguments;
    if (!t.isStringLiteral(first) || first.value !== 'Access-Control-Allow-Origin') return;
    if (!t.isStringLiteral(second) || second.value !== '*') return;
    issues.push(toIssue(node, CORS_WILDCARD, code));
  });

  // Other auth findings (JWT, session, cookie, etc.) come from the regex path.
  const regexFindings = scanAuthRegex(code, parsed.language);
  for (const r of regexFindings) {
    if (r.type === CORS_WILDCARD.name) continue; // handled by AST
    if (issues.some((i) => i.type === r.type && i.line === r.line)) continue;
    issues.push(r);
  }

  return issues;
}

function scanAuthRegex(code: string, lang: Language): SecurityIssue[] {
  // ── PASTE the existing PR 1 scanAuth body here. ──
}
```

- [ ] **Step 4: Run + commit**

```bash
npm test && \
git add src/scanners/auth.ts src/scanners/__tests__/auth.test.ts && \
git commit -m "feat(scanners/auth): AST detects CORS wildcard in setHeader (R-19)

Resolves PR 1 limitation where the CORS regex couldn't see the header
name inside a setHeader() argument. Other auth findings continue via the
regex path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Refactor `path.ts` (R-21)

**Files:**
- Modify: `src/scanners/path.ts`
- Modify: `src/scanners/__tests__/path.test.ts`

- [ ] **Step 1: Append test**

```ts
test('R-21: path multi-hop is flagged', () => {
  const code = `
    const f = req.body.file;
    const norm = f;
    fs.readFile(norm, cb);
  `;
  const issues = scanPath(code, 'typescript');
  assert.ok(issues.some((i) => i.type === 'Path Traversal Risk'));
});
```

- [ ] **Step 2: Run — expect failure**

- [ ] **Step 3: Refactor `src/scanners/path.ts`**

Same shape as injection (uses FS_SINKS):
```ts
import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
  parseCode, walk,
  analyzeTaint, isTainted,
  matchSink, FS_SINKS,
  toIssue,
  type ParseResult,
} from '../utils/ast/index.js';
import { Language } from '../utils/source-helpers.js';

export function scanPath(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const parsed = parseCode(code, lang);
    if (parsed) return scanPathAST(code, parsed);
  }
  return scanPathRegex(code, lang);
}

function scanPathAST(code: string, parsed: ParseResult): SecurityIssue[] {
  const taint = analyzeTaint(parsed);
  const issues: SecurityIssue[] = [];

  walk(parsed.file, (node) => {
    if (!t.isCallExpression(node)) return;
    for (const def of FS_SINKS) {
      const m = matchSink(node, def);
      if (!m.match) continue;
      const arg = node.arguments[m.argIndex];
      if (arg && isTainted(arg as t.Node, taint)) {
        issues.push(toIssue(node, def, code));
        return;
      }
    }

    // Function-summary transitive check for FS sinks.
    const calleeName = resolveCalleeName(node);
    if (!calleeName) return;
    const summary = taint.functionSummaries.get(calleeName);
    if (!summary) return;
    for (let i = 0; i < node.arguments.length; i++) {
      const paramName = summary.paramOrder[i];
      if (!paramName) continue;
      const flows = summary.paramFlows.get(paramName) ?? [];
      if (!flows.some((f) => f.sinkKind === 'fs')) continue;
      if (isTainted(node.arguments[i] as t.Node, taint)) {
        issues.push(toIssue(node, FS_SINKS[0], code));
        return;
      }
    }
  });

  // Non-taint path findings (chmod permissive, hardcoded /tmp, pickle, Zip Slip,
  // etc.) come from the regex path; dedupe.
  const regexFindings = scanPathRegex(code, parsed.language);
  for (const r of regexFindings) {
    if (issues.some((i) => i.type === r.type && i.line === r.line)) continue;
    issues.push(r);
  }

  return issues;
}

function resolveCalleeName(call: t.CallExpression): string | null {
  if (t.isIdentifier(call.callee)) return call.callee.name;
  if (t.isMemberExpression(call.callee) && t.isIdentifier(call.callee.property)) {
    return call.callee.property.name;
  }
  return null;
}

function scanPathRegex(code: string, lang: Language): SecurityIssue[] {
  // ── PASTE the existing PR 1 scanPath body here. ──
}
```

- [ ] **Step 4: Run + commit**

```bash
npm test && \
git add src/scanners/path.ts src/scanners/__tests__/path.test.ts && \
git commit -m "feat(scanners/path): AST detects multi-hop path traversal (R-21)

R-21. Function-summary transitive check applied for fs sinks. Non-taint
path findings continue via the regex path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: Delete `src/utils/ast-parser.ts`

**Files:**
- Delete: `src/utils/ast-parser.ts`

- [ ] **Step 1: Verify no internal callers**

```bash
grep -rn "ast-parser" /Users/cyj/workspace/personal/security-scanner-mcp/src/ 2>/dev/null
```
Expected: only matches inside `src/utils/ast-parser.ts` itself, or nothing.

If there are external references to `ast-parser`, STOP and report. Otherwise:

- [ ] **Step 2: Delete the file**

```bash
rm src/utils/ast-parser.ts
```

- [ ] **Step 3: Build + full test run**

```bash
npm run build && npm test
```
Expected: clean build, all tests pass.

- [ ] **Step 4: Commit**

```bash
git rm src/utils/ast-parser.ts
git commit -m "chore: remove dead src/utils/ast-parser.ts

Replaced by src/utils/ast/ in the same PR. No internal callers. The file
was published in dist/ — deep-import consumers must migrate to
src/utils/ast/ (announced in CHANGELOG 1.2.0).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Bump version + CHANGELOG.md

**Files:**
- Modify: `package.json`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump version**

Edit `package.json`: change `"version": "1.1.0"` to `"version": "1.2.0"`.

- [ ] **Step 2: Prepend 1.2.0 entry to `CHANGELOG.md`**

Insert after the `# Changelog` header and before the `## [1.1.0]` block:

```markdown
## [1.2.0] — 2026-05-20

### Improved (may change behavior)
- JS/TS scanners now use AST-based detection. Function parameter taint
  is detected: `function h(input) { db.query(\`... ${input}\`); } h(req.body.x);`
  now produces an injection finding. If your CI was passing because of
  this gap, expect new findings.
- innerHTML assignment with a literal HTML string is no longer flagged
  (resolves a PR 1 false positive that test code worked around).
- CORS wildcard set via `res.setHeader('Access-Control-Allow-Origin', '*')`
  is now detected (resolves a PR 1 false negative).
- Multi-hop variable chains are detected (was single-hop in 1.1.0).

### Fixed
- Path scanner detects multi-hop file-path flow into `fs.readFile`/`writeFile`.
- Crypto scanner detects multi-hop tainted password storage.

### Removed
- `src/utils/ast-parser.ts` was removed. It was dead infrastructure
  (no internal callers). Deep-import consumers must migrate to
  `src/utils/ast/` (`parseCode`, `walk`, `analyzeTaint`, `isTainted`,
  `matchSink`, sink registries, `toIssue`).

### Internal
- New module `src/utils/ast/` with focused submodules: `parser`,
  `traverse`, `sources`, `sinks`, `taint`, `location`.
- Taint analysis runs a two-pass walk: top-level variable taint with
  fixed-point iteration, plus per-function summaries with per-param
  coloring (avoids the false-flow this would otherwise produce).
- Python / Java / Go inputs continue using the 1.1.0 regex path. AST
  for those languages is not in scope.

### Not in this release
- Return-value taint (`function g(x) { return x; } const t = g(...); sink(t)`).
- Transitive function-call taint (`outer(y) { inner(y); }` where inner
  has a sink).
- Cross-file (inter-procedural) taint.
- AST caching across scanner calls.
- Multi-language AST (planned for a future release; tree-sitter is the
  likely path).
```

- [ ] **Step 3: Verify**

```bash
npm test && npm run demo && npm run build
node -p "require('./package.json').version"
```
Expected: all green, version is `1.2.0`.

- [ ] **Step 4: Commit**

```bash
git add package.json CHANGELOG.md
git commit -m "chore: bump to 1.2.0 + CHANGELOG

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: Final verification

(No code changes — verification only.)

- [ ] **Step 1: Clean build + dist hygiene**

```bash
rm -rf dist && npm run build
find dist -type d -name __tests__
find dist -path '*/examples/*'
find dist -name '*.test.*'
find dist -name 'ast-parser*'
```
Expected: all `find` commands print nothing. `ast-parser` files should not exist in `dist/`.

- [ ] **Step 2: Full test suite**

```bash
npm test
```
Expected: all tests pass. Total should be roughly 100 (PR 1) + ~50 (new ast tests + scanner additions) = ~150.

- [ ] **Step 3: Demo**

```bash
npm run demo
```
Expected: "OK: all expected detections present." If the demo's expected counts no longer match because the AST path catches more, raise the `expectedAtLeast` numbers in `examples/demo.ts` to reflect the new floor.

- [ ] **Step 4: Confirm version + git log**

```bash
node -p "require('./package.json').version"
git log --oneline main..HEAD | head -25
```
Expected: `1.2.0` and a clean ~16-commit sequence.

- [ ] **Step 5: Push and release** (only when user asks)

Same flow as PR 1:
```bash
git checkout main
git merge --ff-only feature/pr2-ast-migration  # or whichever branch name
git tag -a v1.2.0 -m "v1.2.0 — AST migration & function-aware taint (see CHANGELOG)"
git push origin main
git push origin v1.2.0
npm publish
```

---

## Self-Review Checklist (plan author)

- [x] **Spec coverage:**
  - Scope (5 scanners JS/TS, function-arg taint) → Tasks 7a, 7b, 9, 10, 11, 12, 13
  - `src/utils/ast/` module layout → Tasks 2-6, 8
  - `ast-parser.ts` removal → Task 14
  - R-15..R-24 → Tasks 9, 10, 11, 12, 13 (R-15..R-21), Task 9 (R-22, R-23), Task 10 (R-24)
  - T-1..T-10 → Tasks 7a (T-1..T-5), 7b (T-6..T-10)
  - Graceful degrade (parse failure → regex) → Task 9 routing + R-23
  - Multi-language regex preservation → all scanner refactors keep `scanXxxRegex`
  - 1.2.0 + CHANGELOG → Task 15

- [x] **Placeholder scan:** no "TBD"/"TODO"/"add error handling" — every step shows actual code, exact commands, expected output. The phrase "PASTE the existing PR 1 scanXxx body here" is intentional: it points at concrete existing code in the file the engineer is editing, not at imaginary code.

- [x] **Type/method consistency:**
  - `ParseResult`, `TaintState`, `FunctionSummary`, `SinkFlow`, `SinkDefinition`, `SinkKind` — consistent across taint.ts, sinks.ts, location.ts, scanner usages.
  - `analyzeTaint(parsed: ParseResult): TaintState` — single signature throughout.
  - `isTainted(node, state)` — single signature throughout.
  - `matchSink(call, def): { match, argIndex }` — used identically in injection, path, crypto.
  - `matchInnerHtmlAssignment(node) → t.Expression | null` — used only in xss scanner; matches the sinks.ts export.

- [x] **No "Similar to Task N":** each scanner task repeats the routing pattern and sink list inline, even where it's near-identical to the previous task.
