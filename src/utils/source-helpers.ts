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
