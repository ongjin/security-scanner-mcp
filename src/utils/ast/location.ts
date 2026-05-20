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
  return (lines[start.line - 1] ?? '').trim();
}
