export { parseCode } from './parser.js';
export type { ParseResult } from './parser.js';

export { walk } from './traverse.js';
export type { Visitor } from './traverse.js';

export { isUserInputSource } from './sources.js';

export {
  SQL_SINKS, COMMAND_SINKS, MONGO_SINKS, FS_SINKS, INNERHTML_SINKS,
  matchSink, matchInnerHtmlAssignment,
} from './sinks.js';
export type { SinkDefinition, SinkMatchResult } from './sinks.js';

export { analyzeTaint, isTainted } from './taint.js';
export type { TaintState, FunctionSummary, SinkFlow, SinkKind } from './taint.js';

export { toIssue } from './location.js';
