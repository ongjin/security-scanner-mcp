/**
 * AST 기반 코드 분석 유틸리티
 *
 * 정규식보다 정확한 코드 분석을 위해 AST를 파싱합니다.
 *
 * @author zerry
 */

import { parse as babelParse } from '@babel/parser';
import type { File, Node } from '@babel/types';

export interface ASTAnalysisResult {
    hasMatch: boolean;
    locations: Array<{
        line: number;
        column: number;
        code: string;
    }>;
    context?: any;
}

/**
 * JavaScript/TypeScript 코드를 AST로 파싱
 */
export function parseCode(code: string, language: 'javascript' | 'typescript' = 'javascript'): File | null {
    try {
        return babelParse(code, {
            sourceType: 'module',
            plugins: [
                'jsx',
                language === 'typescript' ? 'typescript' : 'flow',
                'decorators-legacy',
                'classProperties',
                'dynamicImport',
                'optionalChaining',
                'nullishCoalescingOperator'
            ],
        });
    } catch (error) {
        console.error('AST 파싱 실패:', error);
        return null;
    }
}

/**
 * AST를 순회하면서 특정 패턴 찾기
 */
export function traverseAST(
    ast: File,
    visitor: (node: Node, parent: Node | null, ancestors: Node[]) => boolean | void
): void {
    const ancestors: Node[] = [];

    function walk(node: Node, parent: Node | null) {
        if (!node || typeof node !== 'object') return;

        ancestors.push(node);

        // visitor 실행 (false 반환 시 하위 노드 탐색 중단)
        const shouldContinue = visitor(node, parent, [...ancestors]);

        if (shouldContinue !== false) {
            // 모든 자식 노드 순회
            for (const key in node) {
                if (key === 'loc' || key === 'range' || key === 'tokens' || key === 'comments') {
                    continue;
                }

                const child = (node as any)[key];

                if (Array.isArray(child)) {
                    child.forEach(item => {
                        if (item && typeof item === 'object' && item.type) {
                            walk(item, node);
                        }
                    });
                } else if (child && typeof child === 'object' && child.type) {
                    walk(child, node);
                }
            }
        }

        ancestors.pop();
    }

    walk(ast.program, null);
}

/**
 * innerHTML 사용 패턴 찾기 (정규식 대신 AST 사용)
 */
export function findInnerHTMLUsage(code: string): ASTAnalysisResult {
    const ast = parseCode(code);
    if (!ast) {
        return { hasMatch: false, locations: [] };
    }

    const locations: Array<{ line: number; column: number; code: string }> = [];

    traverseAST(ast, (node) => {
        // element.innerHTML = value 패턴
        if (node.type === 'AssignmentExpression') {
            const left = node.left;
            if (
                left.type === 'MemberExpression' &&
                left.property.type === 'Identifier' &&
                left.property.name === 'innerHTML'
            ) {
                locations.push({
                    line: node.loc?.start.line || 0,
                    column: node.loc?.start.column || 0,
                    code: extractCodeSnippet(code, node.loc?.start.line || 0)
                });
            }
        }
    });

    return {
        hasMatch: locations.length > 0,
        locations
    };
}

/**
 * SQL Injection 패턴 찾기 (템플릿 리터럴)
 */
export function findSQLInjectionPatterns(code: string): ASTAnalysisResult {
    const ast = parseCode(code);
    if (!ast) {
        return { hasMatch: false, locations: [] };
    }

    const locations: Array<{ line: number; column: number; code: string }> = [];

    traverseAST(ast, (node) => {
        // db.query(`SELECT * FROM users WHERE id = ${userId}`)
        if (node.type === 'CallExpression') {
            const callee = node.callee;

            // query, execute 등의 메서드 호출 체크
            if (
                callee.type === 'MemberExpression' &&
                callee.property.type === 'Identifier' &&
                ['query', 'execute', 'sql'].includes(callee.property.name)
            ) {
                // 첫 번째 인자가 템플릿 리터럴인지 체크
                const firstArg = node.arguments[0];
                if (firstArg && firstArg.type === 'TemplateLiteral') {
                    // SQL 키워드가 있는지 체크
                    const hasSQL = firstArg.quasis.some(quasi =>
                        /SELECT|INSERT|UPDATE|DELETE|FROM|WHERE/i.test(quasi.value.raw)
                    );

                    if (hasSQL && firstArg.expressions.length > 0) {
                        locations.push({
                            line: node.loc?.start.line || 0,
                            column: node.loc?.start.column || 0,
                            code: extractCodeSnippet(code, node.loc?.start.line || 0)
                        });
                    }
                }
            }
        }
    });

    return {
        hasMatch: locations.length > 0,
        locations
    };
}

/**
 * eval() 사용 찾기
 */
export function findEvalUsage(code: string): ASTAnalysisResult {
    const ast = parseCode(code);
    if (!ast) {
        return { hasMatch: false, locations: [] };
    }

    const locations: Array<{ line: number; column: number; code: string }> = [];

    traverseAST(ast, (node) => {
        if (
            node.type === 'CallExpression' &&
            node.callee.type === 'Identifier' &&
            node.callee.name === 'eval'
        ) {
            locations.push({
                line: node.loc?.start.line || 0,
                column: node.loc?.start.column || 0,
                code: extractCodeSnippet(code, node.loc?.start.line || 0)
            });
        }

        // new Function() 패턴도 찾기
        if (
            node.type === 'NewExpression' &&
            node.callee.type === 'Identifier' &&
            node.callee.name === 'Function'
        ) {
            locations.push({
                line: node.loc?.start.line || 0,
                column: node.loc?.start.column || 0,
                code: extractCodeSnippet(code, node.loc?.start.line || 0)
            });
        }
    });

    return {
        hasMatch: locations.length > 0,
        locations
    };
}

/**
 * 하드코딩된 시크릿 찾기 (AST 기반)
 */
export function findHardcodedSecrets(code: string): ASTAnalysisResult {
    const ast = parseCode(code);
    if (!ast) {
        return { hasMatch: false, locations: [] };
    }

    const locations: Array<{ line: number; column: number; code: string }> = [];

    traverseAST(ast, (node) => {
        // const apiKey = "..."
        if (node.type === 'VariableDeclarator') {
            const id = node.id;
            const init = node.init;

            if (
                id.type === 'Identifier' &&
                /api[_-]?key|secret|password|token/i.test(id.name) &&
                init &&
                init.type === 'StringLiteral' &&
                init.value.length > 10
            ) {
                // 주석이나 예제 값 제외
                if (!isExampleValue(init.value)) {
                    locations.push({
                        line: node.loc?.start.line || 0,
                        column: node.loc?.start.column || 0,
                        code: extractCodeSnippet(code, node.loc?.start.line || 0)
                    });
                }
            }
        }

        // { apiKey: "..." } 객체 프로퍼티
        if (node.type === 'ObjectProperty') {
            const key = node.key;
            const value = node.value;

            if (
                key.type === 'Identifier' &&
                /api[_-]?key|secret|password|token/i.test(key.name) &&
                value.type === 'StringLiteral' &&
                value.value.length > 10 &&
                !isExampleValue(value.value)
            ) {
                locations.push({
                    line: node.loc?.start.line || 0,
                    column: node.loc?.start.column || 0,
                    code: extractCodeSnippet(code, node.loc?.start.line || 0)
                });
            }
        }
    });

    return {
        hasMatch: locations.length > 0,
        locations
    };
}

/**
 * 특정 라인의 코드 스니펫 추출
 */
function extractCodeSnippet(code: string, line: number): string {
    const lines = code.split('\n');
    return lines[line - 1]?.trim() || '';
}

/**
 * 예제/더미 값인지 체크
 */
function isExampleValue(value: string): boolean {
    const examplePatterns = [
        /example/i,
        /sample/i,
        /dummy/i,
        /test/i,
        /xxx/i,
        /your[_-]/i,
        /placeholder/i,
        /changeme/i,
    ];

    return examplePatterns.some(pattern => pattern.test(value));
}

/**
 * 코드에서 import 문 찾기
 */
export function findImports(code: string): Array<{ source: string; specifiers: string[] }> {
    const ast = parseCode(code);
    if (!ast) return [];

    const imports: Array<{ source: string; specifiers: string[] }> = [];

    traverseAST(ast, (node) => {
        if (node.type === 'ImportDeclaration') {
            const specifiers = node.specifiers.map(spec => {
                if (spec.type === 'ImportDefaultSpecifier') {
                    return spec.local.name;
                } else if (spec.type === 'ImportSpecifier') {
                    return spec.imported.type === 'Identifier'
                        ? spec.imported.name
                        : '';
                } else if (spec.type === 'ImportNamespaceSpecifier') {
                    return `* as ${spec.local.name}`;
                }
                return '';
            }).filter(Boolean);

            imports.push({
                source: node.source.value,
                specifiers
            });
        }
    });

    return imports;
}
