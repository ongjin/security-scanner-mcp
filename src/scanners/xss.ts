/**
 * XSS (Cross-Site Scripting) 취약점 스캐너
 *
 * 사용자 입력이 HTML에 이스케이프 없이 들어가는 패턴을 찾습니다.
 * React는 기본적으로 안전하지만 dangerouslySetInnerHTML 쓰면 위험해지죠.
 * 그리고 vanilla JS로 innerHTML 쓰는 건 진짜 조심해야 해요.
 *
 * @author zerry
 */

import { SecurityIssue } from '../types.js';

interface XssPattern {
    name: string;
    pattern: RegExp;
    message: string;
    fix: string;
    languages: string[];
}

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
        languages: ['javascript', 'typescript'],
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
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    // 해당 언어에 적용되는 패턴만 필터링
    const applicablePatterns = XSS_PATTERNS.filter(
        p => p.languages.includes(language)
    );

    for (const pattern of applicablePatterns) {
        // 패턴 리셋
        pattern.pattern.lastIndex = 0;

        const matches = code.matchAll(pattern.pattern);

        for (const match of matches) {
            const lineNumber = findLineNumber(code, match.index || 0);
            const line = lines[lineNumber - 1] || '';

            // 주석 스킵
            if (isComment(line, language)) {
                continue;
            }

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

function findLineNumber(code: string, index: number): number {
    const beforeMatch = code.slice(0, index);
    return (beforeMatch.match(/\n/g) || []).length + 1;
}

function isComment(line: string, language: string): boolean {
    const trimmed = line.trim();

    switch (language) {
        case 'python':
            return trimmed.startsWith('#');
        default:
            return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
}
