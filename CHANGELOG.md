# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
