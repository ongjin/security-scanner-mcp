/**
 * 코드 자동 수정 엔진
 *
 * AST 기반 + 템플릿 기반 수정을 결합하여 취약점을 자동으로 수정합니다.
 *
 * @author zerry
 */

import jscodeshift from 'jscodeshift';
import * as prettier from 'prettier';
import { FIX_TEMPLATES, VULNERABILITY_EXPLANATIONS } from './templates/fix-templates.js';
import { SecurityIssue } from '../types.js';

export interface FixResult {
    success: boolean;
    originalCode: string;
    fixedCode: string | null;
    diff: string;
    explanation: string;
    method: 'template' | 'ast' | 'none';
}

/**
 * 템플릿 기반 코드 수정
 */
export async function tryTemplateFix(
    code: string,
    issue: SecurityIssue,
    language: string
): Promise<string | null> {
    const templates = FIX_TEMPLATES[issue.type];
    if (!templates) return null;

    const template = templates.find(t => t.language === language);
    if (!template) return null;

    let fixed = code;
    let hasChanges = false;

    // 각 replacement 적용
    for (const { pattern, replacement } of template.replacements) {
        const before = fixed;

        if (typeof replacement === 'string') {
            fixed = fixed.replace(pattern, replacement);
        } else {
            fixed = fixed.replace(pattern, replacement as any);
        }

        if (before !== fixed) {
            hasChanges = true;
        }
    }

    if (!hasChanges) return null;

    // Prettier로 포맷팅
    try {
        fixed = await prettier.format(fixed, {
            parser: getParser(language),
            semi: true,
            singleQuote: true,
            tabWidth: 4,
        });
    } catch (error) {
        // 포맷팅 실패시 원본 반환
        console.warn('Prettier 포맷팅 실패:', error);
    }

    return fixed;
}

/**
 * AST 기반 코드 수정 (더 정확하지만 복잡함)
 */
export async function astBasedFix(
    code: string,
    issue: SecurityIssue,
    language: string
): Promise<string | null> {
    if (language !== 'javascript' && language !== 'typescript') {
        return null; // 현재는 JS/TS만 지원
    }

    const j = jscodeshift;
    let root;

    try {
        root = j(code);
    } catch (error) {
        console.error('AST 파싱 실패:', error);
        return null;
    }

    let hasChanges = false;

    // innerHTML → textContent 변환
    if (issue.type === 'innerHTML Assignment') {
        root.find(j.AssignmentExpression, {
            left: {
                type: 'MemberExpression',
                property: { name: 'innerHTML' }
            }
        }).forEach(path => {
            if (path.value.left.type === 'MemberExpression' &&
                path.value.left.property.type === 'Identifier') {
                path.value.left.property.name = 'textContent';
                hasChanges = true;
            }
        });
    }

    // eval() → JSON.parse() 변환
    if (issue.type === 'eval() Usage') {
        root.find(j.CallExpression, {
            callee: { name: 'eval' }
        }).forEach(path => {
            // eval(jsonString) → JSON.parse(jsonString)
            path.value.callee = j.memberExpression(
                j.identifier('JSON'),
                j.identifier('parse')
            );
            hasChanges = true;
        });
    }

    // Math.random() → crypto.randomBytes() 변환
    if (issue.type === 'Insecure Random (Math.random)') {
        root.find(j.CallExpression, {
            callee: {
                type: 'MemberExpression',
                object: { name: 'Math' },
                property: { name: 'random' }
            }
        }).forEach(path => {
            // Math.random() → crypto.randomBytes(8).toString('hex')
            const replacement = j.callExpression(
                j.memberExpression(
                    j.callExpression(
                        j.memberExpression(
                            j.identifier('crypto'),
                            j.identifier('randomBytes')
                        ),
                        [j.literal(8)]
                    ),
                    j.identifier('toString')
                ),
                [j.literal('hex')]
            );

            j(path).replaceWith(replacement);
            hasChanges = true;
        });

        // crypto import 추가 (없는 경우)
        const hasImport = root.find(j.ImportDeclaration, {
            source: { value: 'crypto' }
        }).length > 0;

        if (!hasImport && hasChanges) {
            const cryptoImport = j.importDeclaration(
                [j.importNamespaceSpecifier(j.identifier('crypto'))],
                j.literal('crypto')
            );

            root.find(j.Program).get('body', 0).insertBefore(cryptoImport);
        }
    }

    if (!hasChanges) return null;

    return root.toSource({
        quote: 'single',
        tabWidth: 4,
    });
}

/**
 * 코드 수정 실행 (템플릿 → AST 순서로 시도)
 */
export async function fixCode(
    code: string,
    issue: SecurityIssue,
    language: string
): Promise<FixResult> {
    let fixedCode: string | null = null;
    let method: 'template' | 'ast' | 'none' = 'none';

    // 1. 템플릿 기반 수정 시도
    fixedCode = await tryTemplateFix(code, issue, language);
    if (fixedCode) {
        method = 'template';
    }

    // 2. 템플릿에 없으면 AST 기반 수정
    if (!fixedCode) {
        fixedCode = await astBasedFix(code, issue, language);
        if (fixedCode) {
            method = 'ast';
        }
    }

    // 3. Diff 생성
    const diff = fixedCode ? generateDiff(code, fixedCode) : '';

    // 4. 설명 가져오기
    const explanation = getFixExplanation(issue);

    return {
        success: fixedCode !== null,
        originalCode: code,
        fixedCode,
        diff,
        explanation,
        method,
    };
}

/**
 * Diff 생성 (간단한 라인별 비교)
 */
function generateDiff(original: string, fixed: string): string {
    const originalLines = original.split('\n');
    const fixedLines = fixed.split('\n');
    const maxLines = Math.max(originalLines.length, fixedLines.length);

    let diff = '';

    for (let i = 0; i < maxLines; i++) {
        const origLine = originalLines[i] || '';
        const fixedLine = fixedLines[i] || '';

        if (origLine !== fixedLine) {
            if (origLine) {
                diff += `- ${origLine}\n`;
            }
            if (fixedLine) {
                diff += `+ ${fixedLine}\n`;
            }
        } else {
            diff += `  ${origLine}\n`;
        }
    }

    return diff;
}

/**
 * 취약점에 대한 설명 가져오기
 */
export function getFixExplanation(issue: SecurityIssue): string {
    const baseExplanation = VULNERABILITY_EXPLANATIONS[issue.type] || '';

    let explanation = `## 취약점: ${issue.type}\n\n`;
    explanation += `**심각도**: ${issue.severity}\n`;
    explanation += `**위치**: 라인 ${issue.line || '?'}\n\n`;
    explanation += `**문제**:\n${issue.message}\n\n`;
    explanation += `**해결책**:\n${issue.fix}\n`;

    if (baseExplanation) {
        explanation += `\n${baseExplanation}`;
    }

    if (issue.owaspCategory) {
        explanation += `\n**OWASP**: ${issue.owaspCategory}\n`;
    }

    if (issue.cweId) {
        explanation += `**CWE**: ${issue.cweId}\n`;
    }

    return explanation;
}

/**
 * Prettier parser 선택
 */
function getParser(language: string): prettier.BuiltInParserName {
    switch (language) {
        case 'typescript':
            return 'typescript';
        case 'python':
            return 'babel'; // Python은 babel로 fallback
        default:
            return 'babel';
    }
}

/**
 * 수정 결과를 Markdown으로 포맷팅
 */
export function formatFixResult(result: FixResult): string {
    if (!result.success) {
        return `## ❌ 자동 수정 실패\n\n이 취약점은 자동으로 수정할 수 없습니다.\n수동으로 수정해주세요.\n\n${result.explanation}`;
    }

    let output = `## ✅ 자동 수정 제안\n\n`;
    output += `**수정 방법**: ${result.method === 'template' ? '템플릿 기반' : 'AST 기반'}\n\n`;

    output += `### 📝 변경 사항\n\n`;
    output += '```diff\n';
    output += result.diff;
    output += '```\n\n';

    output += `### 📖 설명\n\n`;
    output += result.explanation;

    output += `\n\n### 🔄 수정된 코드\n\n`;
    output += '```javascript\n';
    output += result.fixedCode;
    output += '\n```\n';

    return output;
}
