/**
 * Shared utilities for scanners. Owns line-number calc, comment detection,
 * placeholder detection, and Pass-1 taint variable collection.
 */

export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'java'
  | 'go';

/**
 * Returns the 1-based line number containing `charIndex` in `code`.
 * Index 0 → line 1. A '\n' belongs to the line it terminates.
 * Indices past end saturate at the last line. Negative → 1.
 */
export function lineOf(code: string, charIndex: number): number {
  if (!Number.isFinite(charIndex) || charIndex <= 0) return 1;
  const slice = code.slice(0, charIndex);
  const newlines = slice.match(/\n/g);
  return (newlines ? newlines.length : 0) + 1;
}

/**
 * Whether the line *begins* with a comment marker for the given language.
 * Does not look at the tail of the line — use stripInlineComments for that.
 */
export function isCommentLine(line: string, language: Language): boolean {
  const trimmed = line.trim();
  if (trimmed.length === 0) return false;
  switch (language) {
    case 'python':
      return trimmed.startsWith('#');
    case 'go':
    case 'java':
    case 'javascript':
    case 'typescript':
      return (
        trimmed.startsWith('//') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('*/') ||
        trimmed.startsWith('*')
      );
  }
}

/**
 * Whether charIndex falls inside a block comment (opening with slash-star).
 * Limitation: does not understand strings (rare false positive).
 */
export function isInBlockComment(code: string, charIndex: number): boolean {
  const openIdx = code.indexOf('/*');
  if (openIdx === -1) return false;

  const re = /\/\*[\s\S]*?\*\//g;
  let m: RegExpExecArray | null;
  let lastEnd = -1;
  while ((m = re.exec(code)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (charIndex >= start && charIndex < end) return true;
    if (start > charIndex) return false;
    lastEnd = end;
  }

  // No terminated block matched. Check for unterminated /* after lastEnd.
  const tail = code.indexOf('/*', Math.max(0, lastEnd));
  if (tail !== -1 && tail < charIndex) {
    const closing = code.indexOf('*/', tail + 2);
    if (closing === -1) return true;
  }
  return false;
}

/**
 * Returns the line with any trailing line-comment removed.
 * Quote-aware: // or # inside "..."/'...'/`...` is preserved.
 */
export function stripInlineComments(line: string, language: Language): string {
  const marker = language === 'python' ? '#' : '//';
  let inString: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inString = ch;
      continue;
    }
    if (line.startsWith(marker, i)) {
      return line.slice(0, i);
    }
  }
  return line;
}

const PLACEHOLDER_PHRASES = [
  'example',
  'placeholder',
  '<your',
  'your_',
  'your-',
  'xxxxxxxx',
  'changeme',
  'dummy',
  'sample_',
  'fake_',
  'replace_me',
  'replaceme',
  'todo',
];

/**
 * Whether `value` looks like a placeholder rather than a real secret.
 * Operates on the matched secret VALUE, not on the surrounding line text.
 */
export function isPlaceholderValue(value: string): boolean {
  if (value.length === 0) return false;
  const lower = value.toLowerCase();
  for (const p of PLACEHOLDER_PHRASES) {
    if (lower.includes(p)) return true;
  }
  if (value.length >= 6 && /^(.)\1+$/.test(value)) return true;
  if (value.length >= 8 && shannonEntropy(value) < 2.0) return true;
  return false;
}

function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}
