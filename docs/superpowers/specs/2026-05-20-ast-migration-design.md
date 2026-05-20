# AST Migration & Function-Aware Taint — Design Spec

**Date:** 2026-05-20
**Scope:** PR 2 of the scanner-correctness initiative. Replaces regex-based detection in the 5 call-site scanners with AST-based detection for JS/TS inputs, and introduces single-file taint analysis that includes function-parameter propagation. Python/Java/Go inputs continue using the PR 1 regex path.
**Target version:** `1.1.0` → `1.2.0`
**Prior work:** `docs/superpowers/specs/2026-05-20-scanner-correctness-and-tests-design.md` (PR 1) and `docs/superpowers/plans/2026-05-20-scanner-correctness-and-tests.md`.

## Background

PR 1 added one-hop taint tracking to the call-site scanners using a 2-pass regex approach (`collectTaintedVars` + dynamic alternation in `taintAlternation`). This caught the common AI-generated pattern `const id = req.body.id; db.query(\`... ${id}\`)` but failed on three notable shapes:

1. **Function-parameter taint** — `function h(input) { db.query(\`... ${input}\`); } h(req.body.x);` is not detected, because `input` is not assigned from a tainted source in any matched line.
2. **`innerHTML` regex limitation** — the negative lookahead `(?!['"\`]<)` does not reliably skip literal HTML strings like `el.innerHTML = '<div>safe</div>'`, leading to false positives that we papered over by adjusting the test in PR 1.
3. **CORS in `setHeader`** — `res.setHeader('Access-Control-Allow-Origin', '*')` is not flagged because the regex matches the header name as a top-level token, not as an argument inside a function call.

A useful asset exists at `src/utils/ast-parser.ts` (337 lines) — a babel-parser wrapper plus four AST-based detectors. None of the scanners import these functions; the file is dead infrastructure.

PR 2 rebuilds AST utilities under `src/utils/ast/` with a clean module boundary, removes the unused `ast-parser.ts`, and wires the 5 call-site scanners to use the AST path for JS/TS inputs. The regex path from PR 1 is preserved for Python/Java/Go.

## Scope

### In scope (PR 2)

- New module `src/utils/ast/` with focused submodules: `parser`, `traverse`, `taint`, `sinks`, `sources`, `location`.
- Removal of `src/utils/ast-parser.ts` (no internal callers; CHANGELOG calls out the deep-import surface for npm consumers).
- Single-file taint analysis (`analyzeTaint`) that produces:
  - A multi-hop `taintedVars: Set<string>` for top-level variable assignments
  - A `functionSummaries: Map<string, FunctionSummary>` keyed by function name, with `paramFlows: Map<paramName, SinkFlow[]>` recording which parameters reach which sinks inside the function body.
- AST path in `scanInjection`, `scanXss`, `scanCrypto`, `scanAuth`, `scanPath` for `language === 'javascript' | 'typescript'`. All other languages continue using PR 1's regex path.
- Graceful degradation: if `parseCode` returns `null` (syntax error), the scanner falls back to the regex path for that input.
- Behavior pinned by tests R-15..R-24 (scanner integration) and T-1..T-10 (taint unit tests).
- Version bump `1.1.0` → `1.2.0` and a CHANGELOG entry describing the behavior-change surface area.

### Out of scope

- Python / Java / Go AST. These languages stay on the PR 1 regex path. Multi-language AST is a separate cycle (will likely involve tree-sitter).
- Cross-file (inter-procedural) taint. `import`/`require` resolution is not attempted. Tainted data crossing a module boundary is undetected.
- Return-value taint. Pattern `function g(x) { return x; } const t = g(req.body.x); db.query(\`... ${t}\`)` is not detected. R-22 explicitly pins this as a non-goal.
- Transitive function-call taint. Pattern `function inner(x) { db.query(\`... ${x}\`); } function outer(y) { inner(y); } outer(req.body.x);` is not detected — `outer`'s summary only records sinks *directly* invoked in its body, not sinks reachable via further function calls. Same inter-procedural family as return-value taint; deferred to PR 3.
- AST caching across scanner calls. First measure, then decide whether a cache is justified in a later PR.
- Changes to `secrets.ts`. Secret detection is literal pattern matching; AST adds no leverage there.
- Changes to remediation (`src/remediation/`) or IaC scanners.

## Architecture

### Module layout

```
src/utils/ast/
├── index.ts        // re-exports the public API
├── parser.ts       // parseCode(code, language) → ParseResult | null
├── traverse.ts     // walk(node, visitor) with parent/ancestor tracking
├── taint.ts        // analyzeTaint(parsedFile) → TaintState; isTainted(node, state)
├── sinks.ts        // SQL_SINKS, COMMAND_SINKS, INNERHTML_SINKS, FS_SINKS, MONGO_SINKS;
│                   // matchSink(callExpr, sinkDef) → { match: boolean, argIndex: number }
├── sources.ts      // taint-source matchers (req.body, req.query, request.form, etc.)
└── location.ts     // toIssue(node, sinkDef, code) → SecurityIssue
```

### Public API (`src/utils/ast/index.ts`)

```ts
export { parseCode, ParseResult } from './parser.js';
export { walk, NodePath } from './traverse.js';
export { analyzeTaint, isTainted, TaintState, FunctionSummary } from './taint.js';
export {
  SQL_SINKS, COMMAND_SINKS, INNERHTML_SINKS, FS_SINKS, MONGO_SINKS,
  matchSink, SinkDefinition,
} from './sinks.js';
export { toIssue } from './location.js';
```

`src/utils/ast-parser.ts` is deleted in the same PR.

### Scanner wiring pattern

Each of the 5 call-site scanners follows the same shape. Example (`injection.ts`):

```ts
import * as t from '@babel/types';
import {
  parseCode, analyzeTaint, isTainted,
  matchSink, SQL_SINKS, COMMAND_SINKS, MONGO_SINKS,
  toIssue,
} from '../utils/ast/index.js';

export function scanInjection(code: string, language: string): SecurityIssue[] {
  const lang = language as Language;
  if (lang === 'javascript' || lang === 'typescript') {
    const ast = parseCode(code, lang);
    if (ast) return scanInjectionAST(code, ast);
    // parse failure → fall through to regex path (graceful degradation)
  }
  return scanInjectionRegex(code, lang);
}

function scanInjectionAST(code: string, ast: ParseResult): SecurityIssue[] {
  const taint = analyzeTaint(ast);
  const issues: SecurityIssue[] = [];

  walk(ast, (node) => {
    if (!t.isCallExpression(node)) return;

    for (const sinkDef of [...SQL_SINKS, ...COMMAND_SINKS, ...MONGO_SINKS]) {
      const m = matchSink(node, sinkDef);
      if (!m.match) continue;
      const arg = node.arguments[m.argIndex];
      if (arg && isTainted(arg, taint)) {
        issues.push(toIssue(node, sinkDef, code));
        break;
      }
    }
  });

  return issues;
}

function scanInjectionRegex(code: string, lang: Language): SecurityIssue[] {
  // Existing PR 1 implementation, extracted from the old scanInjection body.
}
```

The same pattern is applied to `xss.ts`, `crypto.ts`, `auth.ts`, `path.ts`. Each scanner imports only the sink sets it needs.

### Core data types

```ts
interface ParseResult {
  file: t.File;       // babel AST root
  language: 'javascript' | 'typescript';
}

interface TaintState {
  /** Variables in the top-level (file) scope assigned (transitively) from a user-input source. */
  taintedVars: Set<string>;

  /** Function name → which parameters flow into which sinks inside the function body. */
  functionSummaries: Map<string, FunctionSummary>;
}

interface FunctionSummary {
  /** paramName → list of sink-reaches found in this function's body. */
  paramFlows: Map<string, SinkFlow[]>;
}

interface SinkFlow {
  sinkKind: 'sql' | 'command' | 'innerHTML' | 'fs' | 'mongo';
  /** The CallExpression node where the sink is invoked. */
  callNode: t.CallExpression;
}

interface SinkDefinition {
  name: string;
  kind: 'sql' | 'command' | 'innerHTML' | 'fs' | 'mongo';
  matches: (call: t.CallExpression) => boolean;
  argIndex: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  fix: string;
  owaspCategory?: string;
  cweId?: string;
}
```

### Taint analysis algorithm

`analyzeTaint(parsedFile)` runs in two passes over the AST:

**Pre-pass — multi-hop top-level variable taint (fixed-point iteration):**
- Walk the file once. For each `VariableDeclarator` or `AssignmentExpression` at the top level (not inside a function body), inspect the RHS.
- If `isTaintedExpression(rhs, state)` is true, add the LHS identifier name to `state.taintedVars`.
- Repeat the walk while any variable is newly added (fixed-point loop, bounded by number of identifiers in the file).

`isTaintedExpression(node, state)`:

| AST pattern | tainted? |
|---|---|
| User-input member access: `req.body.x`, `req.query.x`, `req.params.x`, `request.body`, `event.body`, `ctx.request.body` | yes (matched via `sources.ts`) |
| `process.argv` | yes |
| `process.env.X` | no (trusted) |
| `Identifier 'foo'` where `foo` is in taintedVars | yes |
| `TemplateLiteral` where any expression is tainted | yes |
| `BinaryExpression '+'` where either operand is tainted | yes |
| `MemberExpression` where the object is tainted | yes |
| `CallExpression` where any argument is tainted | yes (conservative) |
| Literal (string / number / boolean / null) | no |
| Anything else | no |

**Main-pass — function summaries:**
- Walk the file again. For each function (`FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`), build a `FunctionSummary`.
- Inside the function body, perform a *local* taint analysis: initialize `localTainted = new Set(paramNames)`. Multi-hop within the body, same algorithm as above.
- Walk the body's `CallExpression`s. For each sink match, for each argument expression, check whether the argument references any parameter (directly or via `localTainted`). If so, record `paramFlows[paramName].push({ sinkKind, callNode })`.

Function names are resolved as follows: `FunctionDeclaration.id.name`, `VariableDeclarator(id, FunctionExpression | ArrowFunctionExpression)` → `id.name`. Anonymous functions are not added to `functionSummaries`. Method definitions on classes are out of scope for PR 2 (covered by the regex fallback if missed).

**Call-site checking — `isTainted(argExpr, state)`:**
- Returns true if the argument is `isTaintedExpression(argExpr, state)`.
- Additionally, the scanner walk inspects each `CallExpression`. If the callee maps to a known `functionSummaries` entry, the scanner checks whether any argument that flows into a tainted parameter is itself tainted. If yes, the call's location is reported as the issue site.

### Why function-summary, not full data-flow

A whole-program data-flow analysis with backward slicing would catch more, but the engineering cost is much higher and false-positive control becomes harder. Function-summary is a known compromise used by lightweight SAST tools: it gives single-hop function-call awareness at the cost of one extra walk per file. R-22 (return-value taint) and inter-procedural flow are explicitly deferred.

### `secrets.ts` and IaC scanners

Unchanged. Secret detection is literal-pattern matching on the raw source; AST inspection of `VariableDeclarator` (init = StringLiteral) would help in some cases but adds complexity for minimal gain over the existing AKIA/`ghp_`/etc. regex set. IaC scanners parse YAML/HCL/Dockerfile — different domain.

## Test Strategy

### Runner

Same as PR 1. The current glob `src/*/__tests__/*.test.ts` matches `src/utils/__tests__` but **not** `src/utils/ast/__tests__`. The plan adds a second glob in PR 2 Task 1:

```json
"test": "node --import tsx --test src/*/__tests__/*.test.ts src/*/*/__tests__/*.test.ts"
```

### Taint unit tests (T-series)

`src/utils/ast/__tests__/taint.test.ts`:

| ID | Scenario | Expectation |
|---|---|---|
| T-1 | `const a = req.body.x` | `taintedVars` includes `a` |
| T-2 | `const a = req.body.x; const b = a;` | `a`, `b` both included (multi-hop) |
| T-3 | `const a = req.body.x; const b = a; const c = b;` | All three included (transitive) |
| T-4 | `const a = process.env.X;` | `a` not included |
| T-5 | `const a = "literal"; const b = a;` | Neither included |
| T-6 | `function h(input) { db.query(\`... ${input}\`); }` | `functionSummaries.get('h').paramFlows.get('input')` contains a SQL sink |
| T-7 | `function h(a, b) { db.query(\`... ${b}\`); }` | `paramFlows.get('b')` contains a SQL sink; `paramFlows.get('a')` is empty |
| T-8 | `function h(input) { const x = input; db.query(\`... ${x}\`); }` | `paramFlows.get('input')` contains a SQL sink (function-body multi-hop) |
| T-9 | `function h() {}` | summary has empty `paramFlows` |
| T-10 | `const h = (input) => db.query(\`... ${input}\`);` | summary built; arrow function recognized |

### Scanner integration tests (R-series, PR 2 additions)

| ID | Scenario | Expectation |
|---|---|---|
| R-15 | function-param taint into SQL: `function h(input) { db.query(\`... ${input}\`); } h(req.body.x);` | At least 1 injection issue |
| R-16 | multi-hop variable chain: `const a = req.body.x; const b = a; const c = b; db.query(\`... ${c}\`);` | At least 1 injection issue |
| R-17 | xss inner-HTML with literal HTML (resolves PR 1 limitation) | 0 issues |
| R-18 | xss inner-HTML with identifier (variable RHS) | 1 issue |
| R-19 | auth CORS in `setHeader('Access-Control-Allow-Origin', '*');` (resolves PR 1 limitation) | 1 issue |
| R-20 | crypto multi-hop password: `const pw = req.body.password; const sanitized = pw; user.password = sanitized;` | 1 issue (Plain Password Storage) |
| R-21 | path multi-hop: `const f = req.body.file; const norm = f; fs.readFile(norm, cb);` | 1 issue (Path Traversal Risk) |
| R-22 | return-value taint (non-goal): `function g(x) { return x; } const t = g(req.body.x); db.query(\`... ${t}\`);` | 0 issues — pinned as PR 2 non-goal |
| R-23 | syntax error: `const x = ;` | 0 issues, no thrown exception (graceful degrade) |
| R-24 | Python code-eval input (`language: 'python'`) | 1 issue via regex fallback (regex path still works) |

### Regression: PR 1 tests stay green

R-1..R-14 from PR 1 remain in their existing test files. They must continue to pass after PR 2 lands; the AST path replaces the JS/TS regex for the 5 call-site scanners, but the secret scanner and IaC scanners are untouched.

### Coverage policy

No coverage percentage gate (same as PR 1). The R-15..R-24 and T-1..T-10 tables are the binding contract.

## Risks & Mitigations

1. **Parse failure swallows detections.**
   `parseCode` returns `null` on syntax error. Without a fallback, the file gets zero detections.
   *Mitigation:* the AST scanner functions call the regex path when parsing fails. R-23 pins graceful degrade.

2. **Function-summary false positives.**
   The matcher records "param flows to sink" but does not require that the param is the only source. A function that mentions its parameter in a non-tainted-sink path could still get summarized.
   *Mitigation:* T-7 explicitly pins that unrelated parameters are not recorded. Further tuning is allowed in PR 3 if real-world false positives appear.

3. **Performance regression.**
   AST parsing is more expensive than regex. Large files (e.g., generated bundles) could see noticeable slowdown.
   *Mitigation:* not addressed in PR 2 (YAGNI). Measure after merge. If slow, PR 3 introduces per-file-hash caching or a single-parse multi-scanner orchestrator.

4. **Behavior change scope.**
   Function-arg taint will catch many findings that PR 1 missed. CI gates may suddenly fail.
   *Mitigation:* `1.1.0` → `1.2.0` minor bump with explicit CHANGELOG note.

5. **External consumers of `ast-parser.ts`.**
   The file is published in the npm `dist/`. Users could be importing it via deep path.
   *Mitigation:* CHANGELOG declares the file removed and lists `src/utils/ast/` as the replacement public surface. Deep imports were never a supported API.

6. **Anonymous function summaries are dropped.**
   `setTimeout(() => db.query(\`... ${req.body.x}\`), 0)` — the arrow is anonymous and has no entry in `functionSummaries`. But the direct sink-call inside it is still walked and checked, so the issue is still found via the direct-call path. T-10 covers named-arrow assignments; anonymous immediately-invoked callbacks land in the "every CallExpression gets matched" walk.

## Rollout

1. One PR. Splitting would leave the codebase in an inconsistent state between scanners.
2. PR description includes:
   - Link to this spec
   - R-15..R-24 and T-1..T-10 tables
   - CHANGELOG 1.2.0 entry verbatim
   - Note that PR 3 (return-value taint, perf, multi-language) is the next planned cycle.
3. After merge: tag `v1.2.0`, push to origin, `npm publish`. Same flow as PR 1's release.
4. PR 3 starts a fresh brainstorm cycle.

## Dependencies

No new runtime deps (`@babel/parser`, `@babel/types` already present). No new devDeps.

## Open Questions

None at design time. All four clarifying questions are resolved:
- Scope: JS/TS 5 call-site scanners + taint flow.
- Taint depth: function-arg propagation, single-file, single-hop function summary.
- Existing `ast-parser.ts`: restructure into `src/utils/ast/` and remove the old file.
- Implementation approach: local taint with function summaries (option B from the brainstorm).
