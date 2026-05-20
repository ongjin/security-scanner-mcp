/**
 * XSS (Cross-Site Scripting) 취약점 스캐너
 *
 * 사용자 입력이 HTML에 이스케이프 없이 들어가는 패턴을 찾습니다.
 * React는 기본적으로 안전하지만 dangerouslySetInnerHTML 쓰면 위험해지죠.
 * 그리고 vanilla JS로 innerHTML 쓰는 건 진짜 조심해야 해요.
 *
 * @author zerry
 */

import * as t from '@babel/types';
import type { SecurityIssue } from '../types.js';
import {
    parseCode, walk,
    INNERHTML_SINKS,
    toIssue,
    type ParseResult,
} from '../utils/ast/index.js';
import {
    lineOf,
    isCommentLine,
    isInBlockComment,
    type Language,
} from '../utils/source-helpers.js';

interface XssPattern {
    name: string;
    pattern: RegExp;
    message: string;
    fix: string;
    languages: Language[];
}

const INNERHTML_ASSIGNMENT_TYPE = 'innerHTML Assignment';

/**
 * XSS 취약점 패턴 정의
 */
const XSS_PATTERNS: XssPattern[] = [
    // React 관련
    {
        name: 'dangerouslySetInnerHTML',
        pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!.*sanitize|.*DOMPurify|.*escape)/gi,
        message: 'dangerouslySetInnerHTML을 sanitize 없이 사용하고 있습니다.',
        fix: 'DOMPurify.sanitize()로 HTML을 정화하세요. 예: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}',
        languages: ['javascript', 'typescript'],
    },

    // Vanilla JS - innerHTML
    {
        name: 'innerHTML Assignment',
        pattern: /\.innerHTML\s*=\s*(?!['"`]<)/gi,
        message: 'innerHTML에 동적 값을 할당하고 있습니다. XSS에 취약합니다.',
        fix: 'textContent를 사용하거나, 꼭 HTML이 필요하면 DOMPurify로 sanitize하세요.',
        languages: ['javascript', 'typescript'],
    },
    {
        name: 'outerHTML Assignment',
        pattern: /\.outerHTML\s*=\s*(?!['"`]<)/gi,
        message: 'outerHTML에 동적 값을 할당하고 있습니다.',
        fix: 'DOM API를 사용해서 안전하게 요소를 생성하세요.',
        languages: ['javascript', 'typescript'],
    },

    // document.write
    {
        name: 'document.write',
        pattern: /document\.write\s*\(/gi,
        message: 'document.write()는 보안상 위험하고 성능도 좋지 않습니다.',
        fix: 'DOM API (createElement, appendChild 등)를 사용하세요.',
        languages: ['javascript', 'typescript'],
    },

    // jQuery
    {
        name: 'jQuery html()',
        pattern: /\$\([^)]+\)\.html\s*\(\s*(?!['"`]<)/gi,
        message: 'jQuery .html()에 동적 값을 넣고 있습니다.',
        fix: '.text()를 사용하거나 HTML이 필요하면 sanitize하세요.',
        languages: ['javascript', 'typescript'],
    },
    {
        name: 'jQuery append with variable',
        pattern: /\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(\s*(?:['"`]\s*<[^>]+>\s*['"`]\s*\+|\$\s*\()/gi,
        message: 'jQuery DOM 조작에 문자열 연결을 사용하고 있습니다.',
        fix: 'DOM 요소를 먼저 생성하고 .text()로 값을 설정한 후 추가하세요.',
        languages: ['javascript', 'typescript'],
    },

    // Vue
    {
        name: 'Vue v-html',
        pattern: /v-html\s*=\s*['"][^'"]+['"]/gi,
        message: 'v-html은 XSS에 취약합니다.',
        fix: '가능하면 v-text나 {{ }} 보간을 사용하세요. v-html이 꼭 필요하면 sanitize하세요.',
        languages: ['javascript', 'typescript'],
    },

    // Angular
    {
        name: 'Angular bypassSecurityTrust',
        pattern: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)/gi,
        message: 'Angular 보안 우회 함수를 사용하고 있습니다.',
        fix: '정말 필요한 경우에만 사용하고, 입력값을 반드시 검증하세요.',
        languages: ['typescript'],
    },

    // Python (Flask, Django)
    {
        name: 'Flask Markup/safe',
        pattern: /Markup\s*\(|mark_safe\s*\(|\|safe\b/gi,
        message: 'HTML을 안전하다고 마킹하고 있습니다. 사용자 입력이 포함되면 위험합니다.',
        fix: '사용자 입력은 절대 mark_safe()에 넣지 마세요.',
        languages: ['python'],
    },
    {
        name: 'Jinja autoescape off',
        pattern: /\{%\s*autoescape\s+false\s*%\}/gi,
        message: 'Jinja2 autoescape를 비활성화했습니다.',
        fix: 'autoescape는 항상 켜두세요. 특정 값만 safe 처리하세요.',
        languages: ['python'],
    },

    // Java (JSP)
    {
        name: 'JSP Expression',
        pattern: /<%=\s*(?:request|session)\./gi,
        message: 'JSP에서 요청 값을 직접 출력하고 있습니다.',
        fix: 'JSTL c:out 태그를 사용하세요. 예: <c:out value="${param.name}" />',
        languages: ['java'],
    },

    // URL-based XSS
    {
        name: 'javascript: URL',
        pattern: /href\s*=\s*['"`]javascript:/gi,
        message: 'javascript: URL은 XSS의 주요 벡터입니다.',
        fix: 'javascript: URL을 사용하지 마세요. onclick 이벤트를 사용하세요.',
        languages: ['javascript', 'typescript', 'python', 'java'],
    },

    // eval 관련 (XSS 통해 악용 가능)
    {
        name: 'eval() Usage',
        pattern: /\beval\s*\(/gi,
        message: 'eval()은 코드 인젝션에 취약합니다.',
        fix: 'eval() 대신 JSON.parse(), Function constructor 등 더 안전한 대안을 사용하세요.',
        languages: ['javascript', 'typescript', 'python'],
    },
    {
        name: 'new Function()',
        pattern: /new\s+Function\s*\(/gi,
        message: 'new Function()은 eval()과 비슷하게 위험합니다.',
        fix: '동적 코드 실행이 꼭 필요한지 재검토하세요.',
        languages: ['javascript', 'typescript'],
    },
];

/**
 * XSS 취약점을 검사합니다.
 */
export function scanXss(code: string, language: string): SecurityIssue[] {
    const lang = language as Language;
    if (lang === 'javascript' || lang === 'typescript') {
        const parsed = parseCode(code, lang);
        if (parsed) {
            return scanXssAST(code, parsed);
        }
        return mergeParseFailureRegexFindings(code, scanXssRegex(code, lang), lang);
    }

    return scanXssRegex(code, lang);
}

function scanXssAST(code: string, parsed: ParseResult): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');
    const innerHtmlDef = INNERHTML_SINKS[0];

    walk(parsed.file, (node) => {
        if (!t.isAssignmentExpression(node)) return;

        const rhs = matchInnerHtmlAssignmentLocal(node);
        if (!rhs) return;
        if (isStaticAstRhs(rhs)) return;
        const line = node.loc?.start.line ? lines[node.loc.start.line - 1] ?? '' : '';
        if (hasSanitization(line)) return;

        issues.push(toInnerHtmlAssignmentIssue(node, innerHtmlDef, code));
    });

    return mergeRegexFindings(issues, scanXssRegex(code, parsed.language));
}

function mergeRegexFindings(
    astIssues: SecurityIssue[],
    regexIssues: SecurityIssue[]
): SecurityIssue[] {
    const issues = [...astIssues];
    const seen = new Set(issues.map(issueKey));

    for (const issue of regexIssues) {
        if (isInnerHtmlAssignmentIssue(issue)) continue;

        const key = issueKey(issue);
        if (seen.has(key)) continue;

        issues.push(issue);
    }

    return issues;
}

function issueKey(issue: SecurityIssue): string {
    return `${issue.type}:${issue.line}:${issue.match}`;
}

function mergeParseFailureRegexFindings(
    code: string,
    regexIssues: SecurityIssue[],
    lang: Language
): SecurityIssue[] {
    const issues = regexIssues.filter(issue => !isInnerHtmlAssignmentIssue(issue));
    return [...issues, ...scanInnerHtmlAssignmentsFallback(code, lang)];
}

function isInnerHtmlAssignmentIssue(issue: SecurityIssue): boolean {
    return issue.type === INNERHTML_ASSIGNMENT_TYPE;
}

function scanInnerHtmlAssignmentsFallback(code: string, lang: Language): SecurityIssue[] {
    const pattern = XSS_PATTERNS.find(p => p.name === INNERHTML_ASSIGNMENT_TYPE);
    if (!pattern) return [];

    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');
    const assignmentPattern = /\.innerHTML\s*=/g;
    let match: RegExpExecArray | null;

    while ((match = assignmentPattern.exec(code)) !== null) {
        const matchIndex = match.index;
        const lineNumber = lineOf(code, matchIndex);
        const line = lines[lineNumber - 1] ?? '';
        const parsed = readAssignmentRhs(code, assignmentPattern.lastIndex);
        if (!parsed) continue;

        if (isCommentLine(line, lang)) continue;
        if (isInBlockComment(code, matchIndex)) continue;
        if (hasSanitization(line)) continue;
        if (isStaticLiteralRhs(parsed.rhs)) continue;

        issues.push({
            type: pattern.name,
            severity: getSeverity(pattern.name),
            message: pattern.message,
            fix: pattern.fix,
            line: lineNumber,
            match: code.slice(matchIndex, parsed.endIndex),
            owaspCategory: 'A03:2021 – Injection',
            cweId: 'CWE-79',
        });
    }

    return issues;
}

function isStaticAstRhs(rhs: t.Expression): boolean {
    const unwrapped = unwrapStaticAstRhs(rhs);
    return t.isStringLiteral(unwrapped) ||
        (t.isTemplateLiteral(unwrapped) && unwrapped.expressions.length === 0);
}

function unwrapStaticAstRhs(rhs: t.Expression): t.Expression {
    let current = rhs;

    while (true) {
        if (t.isParenthesizedExpression(current)) {
            current = current.expression;
            continue;
        }
        if (t.isTSAsExpression(current)) {
            current = current.expression;
            continue;
        }
        if (t.isTSSatisfiesExpression(current)) {
            current = current.expression;
            continue;
        }
        if (t.isTSTypeAssertion(current)) {
            current = current.expression;
            continue;
        }
        if (t.isTSNonNullExpression(current)) {
            current = current.expression;
            continue;
        }
        return current;
    }
}

function readAssignmentRhs(
    code: string,
    startIndex: number
): { rhs: string; endIndex: number } | null {
    let index = startIndex;
    while (index < code.length && /\s/.test(code[index])) {
        index++;
    }

    if (index >= code.length) {
        return null;
    }

    const endIndex = readUntilAssignmentBoundary(code, index);
    return {
        rhs: code.slice(index, endIndex).trim(),
        endIndex,
    };
}

function readUntilAssignmentBoundary(code: string, startIndex: number): number {
    let depth = 0;
    let inString: string | null = null;
    let escaped = false;

    for (let index = startIndex; index < code.length; index++) {
        const ch = code[index];

        if (inString) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch === '\\') {
                escaped = true;
                continue;
            }
            if (ch === inString) {
                inString = null;
            }
            continue;
        }

        if (ch === '\'' || ch === '"' || ch === '`') {
            inString = ch;
            continue;
        }

        if (ch === '(') {
            depth++;
            continue;
        }
        if (ch === ')' && depth > 0) {
            depth--;
            continue;
        }
        if (ch === ';' && depth === 0) {
            return index;
        }
    }

    return code.length;
}

function isStaticLiteralRhs(rhs: string): boolean {
    const unwrapped = normalizeStaticRhs(rhs);
    if (unwrapped.length === 0) return false;
    if (isStaticStringLiteral(unwrapped)) return true;
    return isStaticTemplateLiteral(unwrapped);
}

function normalizeStaticRhs(rhs: string): string {
    let current = rhs.trim();

    while (true) {
        const before = current;
        current = unwrapParenthesizedRhs(current);
        current = stripLeadingAngleAssertion(current);
        current = stripStaticLiteralTsSuffix(current);
        if (current === before) return current;
    }
}

function stripLeadingAngleAssertion(rhs: string): string {
    if (!rhs.startsWith('<')) return rhs;

    let depth = 0;
    for (let i = 0; i < rhs.length; i++) {
        const ch = rhs[i];
        if (ch === '<') {
            depth++;
            continue;
        }
        if (ch === '>') {
            depth--;
            if (depth === 0) {
                const rest = rhs.slice(i + 1).trim();
                if (startsStaticRhsCandidate(rest)) return rest;
                return rhs;
            }
        }
    }

    return rhs;
}

function stripStaticLiteralTsSuffix(rhs: string): string {
    const expressionEnd = readLeadingStaticExpressionEnd(rhs);
    if (expressionEnd === -1) return rhs;

    const suffix = rhs.slice(expressionEnd).trim();
    if (suffix.length === 0) return rhs;
    if (/^!+$/.test(suffix)) return rhs.slice(0, expressionEnd).trim();
    if (isStaticTsAssertionSuffix(suffix)) {
        return rhs.slice(0, expressionEnd).trim();
    }

    return rhs;
}

function isStaticTsAssertionSuffix(suffix: string): boolean {
    const assertion = /^!*\s*(?:as|satisfies)\b([\s\S]+)$/.exec(suffix);
    if (!assertion) return false;

    const typeText = assertion[1].trim();
    return typeText.length > 0 && !hasTopLevelRuntimeContinuation(typeText);
}

function hasTopLevelRuntimeContinuation(value: string): boolean {
    let parenDepth = 0;
    let bracketDepth = 0;
    let braceDepth = 0;
    let angleDepth = 0;
    let inString: string | null = null;
    let escaped = false;

    for (let i = 0; i < value.length; i++) {
        const ch = value[i];
        if (inString) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch === '\\') {
                escaped = true;
                continue;
            }
            if (ch === inString) {
                inString = null;
            }
            continue;
        }

        if (ch === '\'' || ch === '"' || ch === '`') {
            inString = ch;
            continue;
        }

        if (ch === '(') {
            parenDepth++;
            continue;
        }
        if (ch === ')' && parenDepth > 0) {
            parenDepth--;
            continue;
        }
        if (ch === '[') {
            bracketDepth++;
            continue;
        }
        if (ch === ']' && bracketDepth > 0) {
            bracketDepth--;
            continue;
        }
        if (ch === '{') {
            braceDepth++;
            continue;
        }
        if (ch === '}' && braceDepth > 0) {
            braceDepth--;
            continue;
        }
        if (ch === '<') {
            angleDepth++;
            continue;
        }
        if (ch === '>' && angleDepth > 0) {
            angleDepth--;
            continue;
        }
        if (
            ch === '+' &&
            parenDepth === 0 &&
            bracketDepth === 0 &&
            braceDepth === 0 &&
            angleDepth === 0
        ) {
            return true;
        }
    }

    return false;
}

function readLeadingStaticExpressionEnd(rhs: string): number {
    const literalEnd = readLeadingLiteralEnd(rhs);
    if (literalEnd !== -1) return literalEnd;
    if (!rhs.startsWith('(')) return -1;
    return readBalancedParenthesizedPrefixEnd(rhs);
}

function startsStaticRhsCandidate(rhs: string): boolean {
    return rhs.startsWith('\'') || rhs.startsWith('"') || rhs.startsWith('`') || rhs.startsWith('(');
}

function readLeadingLiteralEnd(rhs: string): number {
    const quote = rhs[0];
    if (quote !== '\'' && quote !== '"' && quote !== '`') return -1;

    let escaped = false;
    for (let i = 1; i < rhs.length; i++) {
        const ch = rhs[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === '\\') {
            escaped = true;
            continue;
        }
        if (ch === quote) return i + 1;
    }

    return -1;
}

function readBalancedParenthesizedPrefixEnd(value: string): number {
    let depth = 0;
    let inString: string | null = null;
    let escaped = false;

    for (let i = 0; i < value.length; i++) {
        const ch = value[i];
        if (inString) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch === '\\') {
                escaped = true;
                continue;
            }
            if (ch === inString) {
                inString = null;
            }
            continue;
        }

        if (ch === '\'' || ch === '"' || ch === '`') {
            inString = ch;
            continue;
        }

        if (ch === '(') {
            depth++;
            continue;
        }

        if (ch === ')') {
            depth--;
            if (depth === 0) return i + 1;
            if (depth < 0) return -1;
        }
    }

    return -1;
}

function unwrapParenthesizedRhs(rhs: string): string {
    let current = rhs;

    while (current.startsWith('(') && current.endsWith(')') && hasBalancedOuterParens(current)) {
        current = current.slice(1, -1).trim();
    }

    return current;
}

function hasBalancedOuterParens(value: string): boolean {
    let depth = 0;
    let inString: string | null = null;
    let escaped = false;

    for (let i = 0; i < value.length; i++) {
        const ch = value[i];
        if (inString) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch === '\\') {
                escaped = true;
                continue;
            }
            if (ch === inString) {
                inString = null;
            }
            continue;
        }

        if (ch === '\'' || ch === '"' || ch === '`') {
            inString = ch;
            continue;
        }

        if (ch === '(') {
            depth++;
            continue;
        }

        if (ch === ')') {
            depth--;
            if (depth === 0 && i < value.length - 1) return false;
            if (depth < 0) return false;
        }
    }

    return depth === 0;
}

function isStaticStringLiteral(rhs: string): boolean {
    const quote = rhs[0];
    if (quote !== '\'' && quote !== '"') return false;
    if (rhs[rhs.length - 1] !== quote) return false;

    let escaped = false;
    for (let i = 1; i < rhs.length - 1; i++) {
        const ch = rhs[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === '\\') {
            escaped = true;
            continue;
        }
        if (ch === quote) return false;
    }

    return true;
}

function isStaticTemplateLiteral(rhs: string): boolean {
    if (!rhs.startsWith('`') || !rhs.endsWith('`')) return false;

    let escaped = false;
    for (let i = 1; i < rhs.length - 1; i++) {
        const ch = rhs[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === '\\') {
            escaped = true;
            continue;
        }
        if (ch === '$' && rhs[i + 1] === '{') {
            return false;
        }
    }

    return true;
}

function matchInnerHtmlAssignmentLocal(node: t.AssignmentExpression): t.Expression | null {
    if (node.operator !== '=') return null;
    if (!t.isMemberExpression(node.left)) return null;
    if (node.left.computed) {
        if (t.isStringLiteral(node.left.property) && node.left.property.value === 'innerHTML') {
            return node.right;
        }
        return null;
    }
    if (!t.isIdentifier(node.left.property)) return null;
    return node.left.property.name === 'innerHTML' ? node.right : null;
}

function toInnerHtmlAssignmentIssue(
    node: t.AssignmentExpression,
    innerHtmlDef: typeof INNERHTML_SINKS[0],
    code: string
): SecurityIssue {
    const base = toIssue(node, innerHtmlDef, code);
    const pattern = XSS_PATTERNS.find(p => p.name === INNERHTML_ASSIGNMENT_TYPE);
    return {
        ...base,
        type: INNERHTML_ASSIGNMENT_TYPE,
        severity: getSeverity(INNERHTML_ASSIGNMENT_TYPE),
        message: pattern?.message ?? base.message,
        fix: pattern?.fix ?? base.fix,
    };
}

function scanXssRegex(code: string, lang: Language): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    // 해당 언어에 적용되는 패턴만 필터링
    const applicablePatterns = XSS_PATTERNS.filter(
        p => p.languages.includes(lang)
    );

    for (const pattern of applicablePatterns) {
        // 패턴 리셋
        pattern.pattern.lastIndex = 0;

        const matches = code.matchAll(pattern.pattern);

        for (const match of matches) {
            const matchIndex = match.index ?? 0;
            const lineNumber = lineOf(code, matchIndex);
            const line = lines[lineNumber - 1] ?? '';

            if (isCommentLine(line, lang)) continue;
            if (isInBlockComment(code, matchIndex)) continue;

            // 이미 sanitize 되어있는지 체크 (간단한 휴리스틱)
            if (hasSanitization(line)) {
                continue;
            }

            issues.push({
                type: pattern.name,
                severity: getSeverity(pattern.name),
                message: pattern.message,
                fix: pattern.fix,
                line: lineNumber,
                match: match[0],
                owaspCategory: 'A03:2021 – Injection',
                cweId: 'CWE-79',
            });
        }
    }

    return issues;
}

/**
 * 패턴 이름에 따른 심각도 반환
 */
function getSeverity(patternName: string): 'critical' | 'high' | 'medium' | 'low' {
    // 직접적인 코드 실행은 critical
    if (patternName.includes('eval') || patternName.includes('Function')) {
        return 'critical';
    }
    // innerHTML, v-html 등은 high
    if (patternName.includes('innerHTML') || patternName.includes('html')) {
        return 'high';
    }
    // 나머지는 medium
    return 'medium';
}

/**
 * sanitize 처리가 되어있는지 간단히 체크
 *
 * 완벽하지는 않지만 false positive 줄이는 데 도움됨
 */
function hasSanitization(line: string): boolean {
    const sanitizePatterns = [
        'sanitize',
        'escape',
        'encode',
        'DOMPurify',
        'xss',
        'htmlspecialchars',
        'htmlentities',
    ];

    const lowerLine = line.toLowerCase();
    return sanitizePatterns.some(p => lowerLine.includes(p));
}
