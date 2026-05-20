import type { Node } from '@babel/types';

export type Visitor = (
  node: Node,
  parent: Node | null,
  ancestors: Node[]
) => boolean | void;

const NODE_KEY_SKIP = new Set([
  'loc',
  'range',
  'tokens',
  'comments',
  'leadingComments',
  'trailingComments',
  'innerComments',
  'extra',
]);

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
