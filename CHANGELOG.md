# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

## [1.1.0] — 2026-05-20

### Improved (may change behavior)
- Secret scanner now detects keys assigned to variables whose names contain
  words like `test`, `dummy`, or `your_` (previously skipped). If your CI
  was passing because of this bug, expect new findings.
- Source scanners (injection, crypto, path) now follow one variable
  assignment when looking for tainted input flowing into dangerous sinks.
- Line numbers come from a single tested implementation and are correctly
  1-based at file boundaries. SARIF consumers diffing pre-1.1.0 reports
  may see line shifts.
- Block comments and inline comment tails are now correctly excluded.

### Fixed
- `npm run demo` previously pointed to a non-existent file. A working demo
  now lives at `examples/demo.ts`.

### Added
- Test suite (`npm test`) covering all source scanners, IaC scanners, and
  the new shared utilities in `src/utils/source-helpers.ts`.
- `CHANGELOG.md` (this file).

### Internal
- New module `src/utils/source-helpers.ts` consolidates line-number calc,
  comment detection, placeholder detection, and Pass-1 of the taint flow.
- 50-variable cap in `collectTaintedVars` prevents pathological regex
  growth.

### Not in this release
- AST-based detection (issue #2 in the design spec) is deferred to a
  separate release.
