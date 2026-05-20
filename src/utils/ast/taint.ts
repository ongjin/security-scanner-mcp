import * as t from '@babel/types';
import type { ParseResult } from './parser.js';
import { walk } from './traverse.js';
import { isUserInputSource } from './sources.js';
import {
  COMMAND_SINKS,
  FS_SINKS,
  MONGO_SINKS,
  SQL_SINKS,
  matchSink,
  type SinkDefinition,
  type SinkMatchResult,
} from './sinks.js';

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

  buildFunctionSummaries(parsed, state);
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

  if (t.isObjectExpression(node)) {
    return node.properties.some((property) => {
      if (t.isObjectProperty(property)) {
        return isTaintedExpression(property.value, state);
      }
      if (t.isSpreadElement(property)) {
        return isTaintedExpression(property.argument, state);
      }
      return false;
    });
  }

  if (t.isArrayExpression(node)) {
    return node.elements.some((element) => element && isTaintedExpression(element, state));
  }

  if (
    t.isParenthesizedExpression(node) ||
    t.isTSAsExpression(node) ||
    t.isTSTypeAssertion(node) ||
    t.isTSNonNullExpression(node)
  ) {
    return isTaintedExpression(node.expression, state);
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

const BARE_SQL_SINKS = new Set(['query', 'execute', 'sql', 'raw']);
const BARE_MONGO_SINKS = new Set(['find', 'findOne', 'updateOne', 'deleteOne', 'updateMany', 'deleteMany']);
const CALL_SINKS: SinkDefinition[] = [...SQL_SINKS, ...COMMAND_SINKS, ...MONGO_SINKS, ...FS_SINKS];

type SummarizableFunction =
  | t.FunctionDeclaration
  | t.FunctionExpression
  | t.ArrowFunctionExpression;

type ColorMap = Map<string, Set<string>>;

function buildFunctionSummaries(parsed: ParseResult, state: TaintState): void {
  walk(parsed.file, (node) => {
    if (t.isFunctionDeclaration(node) && node.id) {
      state.functionSummaries.set(node.id.name, summarizeFunction(node));
      return;
    }

    if (
      t.isVariableDeclarator(node) &&
      t.isIdentifier(node.id) &&
      node.init &&
      (t.isFunctionExpression(node.init) || t.isArrowFunctionExpression(node.init))
    ) {
      state.functionSummaries.set(node.id.name, summarizeFunction(node.init));
    }
  });
}

function summarizeFunction(fn: SummarizableFunction): FunctionSummary {
  const paramOrder = identifierParamNames(fn.params);
  const paramFlows: Map<string, SinkFlow[]> = new Map(
    paramOrder.map((param) => [param, []])
  );
  const colors: ColorMap = new Map();

  for (const param of paramOrder) {
    addColors(colors, param, new Set([param]));
  }

  let changed = true;
  while (changed) {
    changed = false;
    walkFunctionBody(fn, (node) => {
      if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
        const sourceColors = expressionColors(node.init, colors);
        if (addColors(colors, node.id.name, sourceColors)) {
          changed = true;
        }
        return;
      }

      if (t.isAssignmentExpression(node) && node.operator === '=' && t.isIdentifier(node.left)) {
        const sourceColors = expressionColors(node.right, colors);
        if (addColors(colors, node.left.name, sourceColors)) {
          changed = true;
        }
      }
    });
  }

  walkFunctionBody(fn, (node) => {
    if (!t.isCallExpression(node)) return;

    for (const sink of CALL_SINKS) {
      const result = matchSummarySink(node, sink);
      if (!result.match || result.argIndex < 0) continue;

      const arg = node.arguments[result.argIndex];
      if (!arg) continue;

      const reachingParams = expressionColors(arg as t.Node, colors);
      for (const param of reachingParams) {
        paramFlows.get(param)?.push({ sinkKind: sink.kind, callNode: node });
      }
    }
  });

  return { paramOrder, paramFlows };
}

function matchSummarySink(call: t.CallExpression, sink: SinkDefinition): SinkMatchResult {
  const base = matchSink(call, sink);
  if (base.match) return base;
  if (!t.isIdentifier(call.callee)) return base;

  if (sink.kind === 'sql' && BARE_SQL_SINKS.has(call.callee.name)) {
    return { match: true, argIndex: 0 };
  }

  if (sink.kind === 'mongo' && BARE_MONGO_SINKS.has(call.callee.name)) {
    return { match: true, argIndex: 0 };
  }

  return base;
}

function identifierParamNames(params: SummarizableFunction['params']): string[] {
  return params.flatMap((param) => (t.isIdentifier(param) ? [param.name] : []));
}

function walkFunctionBody(
  fn: SummarizableFunction,
  visitor: (node: t.Node) => void
): void {
  walk(fn.body, (node) => {
    if (isNestedFunction(node)) return false;
    visitor(node);
  });
}

function isNestedFunction(node: t.Node): boolean {
  return (
    t.isFunctionDeclaration(node) ||
    t.isFunctionExpression(node) ||
    t.isArrowFunctionExpression(node) ||
    t.isObjectMethod(node) ||
    t.isClassMethod(node)
  );
}

function expressionColors(node: t.Node, colors: ColorMap): Set<string> {
  if (t.isIdentifier(node)) {
    return new Set(colors.get(node.name) ?? []);
  }

  if (t.isTemplateLiteral(node)) {
    return unionColors(node.expressions.map((expr) => expressionColors(expr, colors)));
  }

  if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
    return unionColors([
      expressionColors(node.left, colors),
      expressionColors(node.right, colors),
    ]);
  }

  if (t.isMemberExpression(node)) {
    const parts = [expressionColors(node.object, colors)];
    if (node.computed) {
      parts.push(expressionColors(node.property, colors));
    }
    return unionColors(parts);
  }

  if (t.isCallExpression(node) || t.isNewExpression(node)) {
    return new Set();
  }

  if (t.isObjectExpression(node)) {
    return unionColors(
      node.properties.map((property) => {
        if (t.isObjectProperty(property)) {
          return expressionColors(property.value, colors);
        }
        if (t.isSpreadElement(property)) {
          return expressionColors(property.argument, colors);
        }
        return new Set<string>();
      })
    );
  }

  if (t.isArrayExpression(node)) {
    return unionColors(
      node.elements.map((element) => (element ? expressionColors(element, colors) : new Set()))
    );
  }

  if (t.isConditionalExpression(node)) {
    return unionColors([
      expressionColors(node.consequent, colors),
      expressionColors(node.alternate, colors),
    ]);
  }

  if (t.isAssignmentExpression(node)) {
    return expressionColors(node.right, colors);
  }

  if (t.isUnaryExpression(node) || t.isAwaitExpression(node) || t.isYieldExpression(node)) {
    return node.argument ? expressionColors(node.argument, colors) : new Set();
  }

  if (t.isTaggedTemplateExpression(node)) {
    return expressionColors(node.quasi, colors);
  }

  if (
    t.isParenthesizedExpression(node) ||
    t.isTSAsExpression(node) ||
    t.isTSTypeAssertion(node) ||
    t.isTSNonNullExpression(node)
  ) {
    return expressionColors(node.expression, colors);
  }

  if (t.isSpreadElement(node)) {
    return expressionColors(node.argument, colors);
  }

  return new Set();
}

function addColors(colors: ColorMap, name: string, sourceColors: Set<string>): boolean {
  if (sourceColors.size === 0) return false;

  const existing = colors.get(name) ?? new Set<string>();
  const before = existing.size;
  for (const color of sourceColors) {
    existing.add(color);
  }
  colors.set(name, existing);
  return existing.size !== before;
}

function unionColors(colorSets: Set<string>[]): Set<string> {
  const merged = new Set<string>();
  for (const colorSet of colorSets) {
    for (const color of colorSet) {
      merged.add(color);
    }
  }
  return merged;
}
