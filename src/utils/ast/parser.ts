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
