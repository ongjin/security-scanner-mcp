import * as t from '@babel/types';

/**
 * Whether `node` represents a user-controlled input source.
 *
 * Recognized patterns (top of expression, in any nesting level the caller
 * passes in):
 *   req.body / req.query / req.params / req.cookies / req.headers / req.url
 *   request.body / request.query / request.params / request.form
 *   ctx.request.body / ctx.request.query / ...
 *   event.body / event.queryStringParameters / event.pathParameters
 *   process.argv
 *
 * Explicitly NOT recognized (trusted):
 *   process.env.*
 */
export function isUserInputSource(node: t.Node): boolean {
  if (t.isMemberExpression(node)) {
    return matchesMember(node);
  }
  return false;
}

const USER_INPUT_FIELDS = new Set([
  'body', 'query', 'params', 'cookies', 'headers', 'url', 'form', 'args',
  'queryStringParameters', 'pathParameters', 'multiValueHeaders',
]);

const TOP_LEVEL_USER_OBJECTS = new Set(['req', 'request', 'event']);

function matchesMember(me: t.MemberExpression): boolean {
  let current: t.Node = me;
  while (t.isMemberExpression(current)) {
    const object = current.object;
    const property = current.property;

    if (t.isIdentifier(object) && t.isIdentifier(property)) {
      if (TOP_LEVEL_USER_OBJECTS.has(object.name) && USER_INPUT_FIELDS.has(property.name)) {
        return true;
      }
      if (object.name === 'process' && property.name === 'argv') return true;
      if (object.name === 'process' && property.name === 'env') return false;
    }

    if (t.isMemberExpression(object) && t.isIdentifier(property) && USER_INPUT_FIELDS.has(property.name)) {
      const inner = object;
      if (t.isIdentifier(inner.object) && t.isIdentifier(inner.property)) {
        if (inner.object.name === 'ctx' && inner.property.name === 'request') return true;
      }
    }

    current = current.object;
  }
  return false;
}
