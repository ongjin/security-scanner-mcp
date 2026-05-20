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

export function analyzeTaint(parsed: ParseResult): TaintState {
  const state: TaintState = {
    taintedVars: new Set(),
    functionSummaries: new Map(),
  };

  let changed = true;
  while (changed) {
    changed = false;
    walk(parsed.file, (node, _parent, ancestors) => {
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
    return isTaintedExpression(node.object, state);
  }

  if (t.isCallExpression(node)) {
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
