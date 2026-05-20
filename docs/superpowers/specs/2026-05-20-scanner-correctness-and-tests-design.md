# Scanner Correctness & Test Infrastructure — Design Spec

**Date:** 2026-05-20
**Scope:** PR 1 of a 2-PR sequence to address 7 issues identified during code review of the regex-based scanners. PR 2 (AST migration, issue #2) is deferred to its own brainstorm cycle.
**Target version:** `1.0.9` → `1.1.0`

## Background

Code review revealed seven concrete issues in the native scanners:

1. **No tests.** `package.json` declares `"test": "node --test"` but no test files exist anywhere in the repo.
2. **Native scanners are regex-only.** Babel/jscodeshift are dependencies but only used by remediation, never by detection. (Deferred to PR 2.)
3. **Regex is too narrow.** Injection/command patterns require user-input source tokens (`req.`, `body.`, `params.`) to appear literally in the same call site; a single variable hop hides them.
4. **`isCommentOrExample` over-skips.** `secrets.ts` skips any line whose text contains `test`, `your_`, `dummy`, etc., causing real secrets to be missed when the variable name contains such a word.
5. **Line-number calculation is suspect.** `secrets.ts:147-155` uses a charCount-accumulator with a `>` comparison that is off-by-one in plausible boundary cases. Untested.
6. **`npm run demo` is broken.** Points to `examples/demo.ts` but the `examples/` directory does not exist.
7. **Comment skipping is naive.** Only `line.trim().startsWith(...)` — inline comments, block comments, and strings containing comment-like substrings are mishandled.

The sandbox path (`scan-in-sandbox`) is sound — it delegates to Trivy / GitLeaks / Checkov inside a hardened Docker container. This spec does not touch it.

## Scope

### In scope (PR 1)

- `#1` Test infrastructure on `node:test` + `tsx`; at least one positive and one negative test per scanner; targeted regression tests per issue below.
- `#3` One-hop taint tracking via 2-pass regex (Approach A; see below) across the **5 call-site scanners**: `injection`, `xss`, `crypto`, `auth`, `path`. `secrets` and `dependencies` are excluded because they match literal patterns and manifest entries respectively — they have no call site where taint flow is meaningful. They still receive #7 (comment handling) and #5 (line numbers) via the shared utility.
- `#4` Fix `isCommentOrExample` so variable-name text does not mask real secrets; placeholder detection moves to the *matched value*, not the whole line.
- `#5` Replace line-number calculation with a single shared utility, behavior pinned by tests.
- `#6` Write a real `examples/demo.ts` that exercises secrets, injection, xss, and IaC scanners on intentionally vulnerable code.
- `#7` Strengthen comment handling: line comments, block comments, inline comments. Implemented in shared utility with tests.
- Version bump `1.0.9` → `1.1.0` (minor) + new `CHANGELOG.md` calling out behavior changes.

### Out of scope

- `#2` AST-based detection migration. Separate brainstorm cycle.
- Adding new vulnerability rules. PR 1 only improves accuracy and stability of existing rules.
- Changes to `src/remediation/` (auto-fix engine).
- Changes to `src/external/` (CVE/OWASP API integration).
- Changes to `src/sandbox/`.
- CI workflow setup (`.github/workflows/*`).
- Coverage gates.

## Architecture

### New files

```
src/utils/source-helpers.ts                            (shared scanning utilities)
src/utils/__tests__/source-helpers.test.ts
src/scanners/__tests__/secrets.test.ts
src/scanners/__tests__/injection.test.ts
src/scanners/__tests__/xss.test.ts
src/scanners/__tests__/crypto.test.ts
src/scanners/__tests__/auth.test.ts
src/scanners/__tests__/path.test.ts
src/scanners/__tests__/dependencies.test.ts
src/iac-scanners/__tests__/dockerfile.test.ts
src/iac-scanners/__tests__/kubernetes.test.ts
src/iac-scanners/__tests__/terraform.test.ts
examples/demo.ts
CHANGELOG.md
```

### Modified files

```
src/scanners/secrets.ts        # #4 value-vs-line split, #5 line calc, #7 comments
src/scanners/injection.ts      # #3 taint tracking, #5, #7
src/scanners/xss.ts            # #3, #5, #7
src/scanners/auth.ts           # #3, #5, #7
src/scanners/crypto.ts         # #3, #5, #7
src/scanners/path.ts           # #3, #5, #7
src/scanners/dependencies.ts   # #5, #7 (no #3 — manifest scanner)
package.json                   # version 1.1.0; test script uses --import tsx/esm
tsconfig.json                  # exclude __tests__ and examples from build
README.md, README.en.md        # minor mentions if needed
```

### Shared module: `src/utils/source-helpers.ts`

Detection rules (the pattern lists) stay inside each scanner. Boilerplate logic moves into shared, tested helpers:

- `lineOf(code: string, charIndex: number): number`
  Single source of truth for line numbers. 1-based. Index 0 → line 1. Index immediately after a `\n` → next line. Tested for boundaries.

- `isCommentLine(line: string, language: Language): boolean`
  Whether a *line begins* with a comment marker. Recognizes `//`, `#`, `--`, `/*`, `*` (continuation). Does not attempt to parse strings.

- `isInBlockComment(code: string, charIndex: number): boolean`
  Pre-computes block-comment ranges (`/* ... */`) once per call and tests membership. Safe for sources without block comments.

- `stripInlineComments(line: string, language: Language): string`
  Returns the line with the inline-comment tail removed. Used to test whether the *non-comment portion* of a line contains the match. Quote-aware: a `//` inside `"..."` or `'...'` is preserved.

- `collectTaintedVars(code: string, language: Language): Set<string>`
  First pass of Approach A. Per-language patterns extract identifiers assigned from user-input sources. Caps at 50 identifiers; beyond that, returns the empty set and logs once (avoid pathological regex expansion).

- `isPlaceholderValue(value: string): boolean`
  Operates on the **matched secret value**, not the surrounding line. Heuristics: presence of `example`, `placeholder`, `<your`, `xxxx+`, `changeme`, `dummy`, all-same-character; very low entropy (Shannon < 2.0).

- `escapeRegex(s: string): string`
  Standard regex escape for safe alternation building.

### Approach A — one-hop taint tracking

**Pass 1.** For each language, run a fixed regex against the full source to collect identifier names of variables assigned from user-input sources.

| Language | Assignment pattern | Taint sources |
|---|---|---|
| JS/TS | `(?:const\|let\|var)\s+(\w+)\s*=\s*<SRC>` | `req.body.`, `req.query.`, `req.params.`, `request.body.`, `event.body`, `ctx.request.body`, `process.argv` |
| Python | `(\w+)\s*=\s*<SRC>` | `request.form`, `request.args`, `request.json`, `flask.request.`, `sys.argv` |
| Java | `(?:String\|int\|Object)\s+(\w+)\s*=\s*<SRC>` | `request.getParameter(`, `@RequestParam`, `@PathVariable` |
| Go | `(\w+)\s*(?::=\|=)\s*<SRC>` | `r.URL.Query()`, `r.FormValue(`, `r.PostForm` |

`process.env` is *not* a taint source (environment is assumed trusted). Function-parameter declarations (`function handler(req) { ... }`) are *not* tracked — too broad without semantic info.

**Pass 2.** Existing dangerous-call patterns are extended with a dynamically composed alternation of the collected variable names, each `\b`-bounded and `escapeRegex`-passed.

Example:
```
Static:    /(?:exec|spawn)\s*\([^)]*(?:req\.|params\.|body\.|query\.|input)/gi
Composed:  /(?:exec|spawn)\s*\([^)]*(?:req\.|params\.|body\.|query\.|input|\buserId\b|\bcmd\b)/gi
```

Cap: if `collectTaintedVars` returns > 50 identifiers, the scanner falls back to the static pattern only and emits a single info-level log line. This prevents catastrophic regex blowup.

### `isCommentOrExample` fix (issue #4)

Current behavior (`secrets.ts:188-215`):
```ts
const lowerLine = line.toLowerCase();
return examplePatterns.some(p => lowerLine.includes(p));
```
This skips `const test_api_key = "AKIA1234567890123456"` because the line contains `test`.

New behavior, replacing the body:
```ts
if (isCommentLine(line, language)) return true;
if (isInBlockComment(code, matchIndex)) return true;
if (isPlaceholderValue(matchedValue)) return true;
return false;
```

The placeholder check moves to the matched secret *value*, never the surrounding identifier or line text.

### Line-number fix (issue #5)

`secrets.ts:147-155` is replaced with a call to `lineOf(code, match.index)`. The shared implementation is the only one in the codebase and is pinned by R-7 and R-8 tests (see below).

### Comment-handling strengthening (issue #7)

For each match, before reporting, scanners call:
```ts
if (isCommentLine(lines[lineNumber - 1], language)) continue;
if (isInBlockComment(code, match.index)) continue;
// Optional: drop matches that fall entirely inside an inline-comment tail
if (matchIsInsideInlineComment(line, language, columnOfMatch)) continue;
```

`secrets.ts` already has an example-pattern check; that is consolidated into the new helpers. Other scanners gain consistent comment handling that they currently lack or duplicate.

### Demo (`examples/demo.ts`)

A short script that:
1. Defines a string constant containing several known vulnerable snippets (one per scanner family).
2. Runs each scanner against it.
3. Prints a table of `{scanner, count}` to stdout.

The expected counts are encoded both in the demo's own assertions and in README. If a future change accidentally drops detections, `npm run demo` exits non-zero.

### `CHANGELOG.md`

```markdown
# Changelog

## 1.1.0 — 2026-05-20

### Improved (may change behavior)
- Secret scanner now detects keys assigned to variables whose names contain
  words like `test`, `dummy`, or `your_` (previously skipped). If your CI
  was passing because of this bug, expect new findings.
- All source scanners now follow one variable assignment when looking for
  tainted input flowing into dangerous sinks. `const id = req.body.id;
  db.query(\`... ${id}\`)` is now flagged.
- Line numbers in scanner output are now consistently 1-based and correct
  at file boundaries. SARIF consumers diffing against pre-1.1.0 reports
  will see line shifts.

### Fixed
- `npm run demo` now exists and runs.
- Inline and block comments are correctly excluded from scanning.

### Added
- Test suite (`npm test`) covering all scanners and the new shared utilities.
```

## Test Strategy

### Runner

`node --test --import tsx/esm "src/**/__tests__/*.test.ts"` invoked via `npm test`. No new dependencies (tsx is already a devDep).

### Build hygiene

`tsconfig.json` excludes `**/__tests__/**` and `examples/**` so `dist/` stays clean. Verified by inspecting `dist/` after `npm run build` — no `__tests__` directories should appear.

### Regression matrix

The following cases are the binding acceptance criteria. Each is encoded as a `node:test` test.

| ID | Scenario | Expected |
|---|---|---|
| R-1 | `const k = "AKIA..."` in plain code | 1 issue, type "AWS Access Key" |
| R-2 | `const test_api_key = "AKIA..."` (var name contains "test") | 1 issue — **regression for #4** |
| R-3 | `const k = "your_api_key_here"` | 0 issues (placeholder value) |
| R-4 | `// example: AKIA...` line comment | 0 issues |
| R-5 | `/* sample: AKIA... */` block comment | 0 issues — **regression for #7** |
| R-6 | `const k = "..."; // AKIA...` inline-comment tail with key | 0 issues |
| R-7 | Key on Nth line of multi-line source | `issue.line === N` |
| R-8 | Match at index 0 of source | `issue.line === 1` — **regression for #5** |
| R-9 | `const id = req.body.id; db.query(\`... ${id}\`)` | 1 injection issue — **regression for #3** |
| R-10 | Function-parameter taint (`function h(input) { db.query(... ${input}) }`) | 0 issues (PR 1 non-goal, pinned to avoid scope creep) |
| R-11 | > 50 tainted variables collected | Static patterns only, no crash, no exponential regex |
| R-12 | Dockerfile `USER root` | 1 issue (existing IaC scanner) |
| R-13 | K8s `privileged: true` | 1 issue |
| R-14 | Terraform `0.0.0.0/0` | 1 issue |

Each scanner additionally has at least one happy-path positive test and one trivial negative test (empty input → no issues).

### Coverage policy

No coverage percentage gate. The matrix above is the spec. Adding tests beyond it is welcome; adding tests *only* to satisfy a coverage number is not.

## Risks & Mitigations

1. **Downstream CI breakage from #4 fix.**
   Users running `--fail-on critical` may suddenly see new findings.
   *Mitigation:* `1.1.0` minor bump and explicit CHANGELOG note.

2. **Test files leaking into `dist/`.**
   *Mitigation:* `tsconfig.json` exclude + post-build inspection during this PR.

3. **Regex blowup from too many tainted vars.**
   *Mitigation:* Hard cap at 50 identifiers in `collectTaintedVars`. Tested by R-11.

4. **Inline-comment heuristic missing strings.**
   `"http://example.com"` contains `//` — naive stripping would truncate the line.
   *Mitigation:* `stripInlineComments` is quote-aware. Tested directly.

5. **Detection-accuracy claims are qualitative.**
   No ground-truth corpus.
   *Mitigation:* The R-1..R-14 matrix is the contract. The demo encodes expected counts so regressions show up immediately.

## Rollout

1. One PR for all of the above. Splitting further would make the test infrastructure land separately from the things it tests, which defeats the point.
2. PR description includes the R-1..R-14 table and the CHANGELOG entry.
3. After merge: tag `v1.1.0`, `npm publish`.
4. PR 2 (issue #2, AST migration) starts a new brainstorm cycle from scratch.

## Open Questions

None remaining at design time. All four clarifying questions are resolved:
- Test runner: `node:test`
- Detection-improvement scope: all 7 source scanners
- Demo fate: implement it
- Version-bump policy: minor + CHANGELOG
- Approach for #3: A (2-pass regex with one-hop taint tracking)
