/**
 * 샌드박스 스캔 Entrypoint
 *
 * Docker 컨테이너 내부에서 실행되는 스캔 스크립트입니다.
 * 코드 파일을 읽어서 보안 스캔을 수행하고 결과를 JSON으로 출력합니다.
 *
 * @author zerry
 */

import { scanSecrets } from '../scanners/secrets.js';
import { scanInjection } from '../scanners/injection.js';
import { scanXss } from '../scanners/xss.js';
import { scanCrypto } from '../scanners/crypto.js';
import { scanAuth } from '../scanners/auth.js';
import { scanPath } from '../scanners/path.js';
import { SecurityIssue } from '../types.js';
import * as fs from 'fs';

/**
 * 언어 자동 감지
 */
function detectLanguage(code: string): string {
    if (code.includes('import ') || code.includes('export ') || code.includes('const ') || code.includes('let ')) {
        if (code.includes('interface ') || code.includes(': string') || code.includes(': number')) {
            return 'typescript';
        }
        return 'javascript';
    }
    if (code.includes('def ') || code.includes('import ') && code.includes('from ')) {
        return 'python';
    }
    if (code.includes('public class ') || code.includes('private ') || code.includes('package ')) {
        return 'java';
    }
    if (code.includes('func ') || code.includes('package main')) {
        return 'go';
    }
    return 'javascript'; // 기본값
}

/**
 * 메인 스캔 함수
 */
async function scanCodeInSandbox() {
    try {
        // 환경 변수에서 설정 읽기
        const codeFilePath = process.env.SCAN_CODE_FILE || '/tmp/code.txt';
        const language = process.env.SCAN_LANGUAGE || 'auto';

        // 코드 파일 읽기
        if (!fs.existsSync(codeFilePath)) {
            console.error(JSON.stringify({
                success: false,
                error: `Code file not found: ${codeFilePath}`
            }));
            process.exit(1);
        }

        const code = fs.readFileSync(codeFilePath, 'utf-8');

        // 언어 감지
        const detectedLang = language === 'auto' ? detectLanguage(code) : language;

        // 보안 스캔 실행
        const issues: SecurityIssue[] = [];

        issues.push(...scanSecrets(code));
        issues.push(...scanInjection(code, detectedLang));
        issues.push(...scanXss(code, detectedLang));
        issues.push(...scanCrypto(code, detectedLang));
        issues.push(...scanAuth(code, detectedLang));
        issues.push(...scanPath(code, detectedLang));

        // 결과를 JSON으로 출력
        const result = {
            success: true,
            language: detectedLang,
            issuesCount: issues.length,
            issues: issues.map(issue => ({
                type: issue.type,
                severity: issue.severity,
                message: issue.message,
                fix: issue.fix,
                line: issue.line,
                match: issue.match,
                owaspCategory: issue.owaspCategory,
                cweId: issue.cweId,
            })),
            summary: {
                critical: issues.filter(i => i.severity === 'critical').length,
                high: issues.filter(i => i.severity === 'high').length,
                medium: issues.filter(i => i.severity === 'medium').length,
                low: issues.filter(i => i.severity === 'low').length,
            }
        };

        console.log(JSON.stringify(result, null, 2));
        process.exit(0);

    } catch (error) {
        console.error(JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : String(error)
        }));
        process.exit(1);
    }
}

// 실행
scanCodeInSandbox();
