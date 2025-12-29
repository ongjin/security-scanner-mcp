/**
 * 보안 취약점 자동 수정 템플릿
 *
 * 각 취약점 타입별로 정규식 기반 수정 패턴을 정의합니다.
 *
 * @author zerry
 */

export interface FixReplacement {
    pattern: RegExp;
    replacement: string | ((match: string, ...args: any[]) => string);
    description: string;
}

export interface FixTemplate {
    language: string;
    replacements: FixReplacement[];
    explanation: string;
}

/**
 * 취약점 타입별 수정 템플릿
 */
export const FIX_TEMPLATES: Record<string, FixTemplate[]> = {
    'innerHTML Assignment': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /\.innerHTML\s*=\s*([^;]+)/g,
                    replacement: '.textContent = $1 // 보안: XSS 방지를 위해 textContent 사용',
                    description: 'innerHTML을 textContent로 변경'
                }
            ],
            explanation: 'innerHTML은 HTML을 파싱하므로 XSS 공격에 취약합니다. textContent는 텍스트로만 처리하여 안전합니다.'
        },
        {
            language: 'typescript',
            replacements: [
                {
                    pattern: /\.innerHTML\s*=\s*([^;]+)/g,
                    replacement: '.textContent = $1 // 보안: XSS 방지를 위해 textContent 사용',
                    description: 'innerHTML을 textContent로 변경'
                }
            ],
            explanation: 'innerHTML은 HTML을 파싱하므로 XSS 공격에 취약합니다. textContent는 텍스트로만 처리하여 안전합니다.'
        }
    ],

    'Template Literal SQL': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /db\.query\s*\(\s*`([^`]*)`\s*\)/g,
                    replacement: (match, sql) => {
                        // `SELECT * FROM users WHERE id = ${userId}`
                        // → db.query('SELECT * FROM users WHERE id = ?', [userId])
                        const params: string[] = [];
                        const parameterizedSQL = sql.replace(/\$\{([^}]+)\}/g, (_: string, param: string) => {
                            params.push(param.trim());
                            return '?';
                        });

                        return `db.query('${parameterizedSQL}', [${params.join(', ')}]) // 보안: Prepared Statement 사용`;
                    },
                    description: '템플릿 리터럴을 Prepared Statement로 변환'
                }
            ],
            explanation: 'SQL 쿼리에 변수를 직접 삽입하면 SQL Injection에 취약합니다. Prepared Statement를 사용하세요.'
        },
        {
            language: 'typescript',
            replacements: [
                {
                    pattern: /db\.query\s*\(\s*`([^`]*)`\s*\)/g,
                    replacement: (match, sql) => {
                        const params: string[] = [];
                        const parameterizedSQL = sql.replace(/\$\{([^}]+)\}/g, (_: string, param: string) => {
                            params.push(param.trim());
                            return '?';
                        });

                        return `db.query('${parameterizedSQL}', [${params.join(', ')}]) // 보안: Prepared Statement 사용`;
                    },
                    description: '템플릿 리터럴을 Prepared Statement로 변환'
                }
            ],
            explanation: 'SQL 쿼리에 변수를 직접 삽입하면 SQL Injection에 취약합니다. Prepared Statement를 사용하세요.'
        }
    ],

    'Weak Hash (MD5)': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/g,
                    replacement: "crypto.createHash('sha256') // 보안: MD5는 충돌 공격에 취약",
                    description: 'MD5를 SHA-256으로 변경'
                }
            ],
            explanation: 'MD5는 더 이상 안전하지 않습니다. SHA-256 이상을 사용하세요.'
        },
        {
            language: 'python',
            replacements: [
                {
                    pattern: /hashlib\.md5\s*\(/g,
                    replacement: 'hashlib.sha256( # 보안: MD5는 충돌 공격에 취약',
                    description: 'MD5를 SHA-256으로 변경'
                }
            ],
            explanation: 'MD5는 더 이상 안전하지 않습니다. SHA-256 이상을 사용하세요.'
        }
    ],

    'Weak Hash (SHA1)': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /crypto\.createHash\s*\(\s*['"]sha1?['"]\s*\)/g,
                    replacement: "crypto.createHash('sha256') // 보안: SHA-1은 더 이상 안전하지 않음",
                    description: 'SHA-1을 SHA-256으로 변경'
                }
            ],
            explanation: 'SHA-1은 2017년 충돌 공격이 실제로 성공했습니다. SHA-256 이상을 사용하세요.'
        }
    ],

    'Insecure Random (Math.random)': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /Math\.random\s*\(\s*\)/g,
                    replacement: 'crypto.randomBytes(8).toString(\'hex\') // 보안: Math.random은 예측 가능',
                    description: 'Math.random()을 crypto.randomBytes()로 변경'
                }
            ],
            explanation: 'Math.random()은 예측 가능하므로 보안 용도로 사용하면 안됩니다.'
        },
        {
            language: 'typescript',
            replacements: [
                {
                    pattern: /Math\.random\s*\(\s*\)/g,
                    replacement: 'crypto.randomBytes(8).toString(\'hex\') // 보안: Math.random은 예측 가능',
                    description: 'Math.random()을 crypto.randomBytes()로 변경'
                }
            ],
            explanation: 'Math.random()은 예측 가능하므로 보안 용도로 사용하면 안됩니다.'
        }
    ],

    'AWS Access Key': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /(const|let|var)\s+(\w*[Aa]ws\w*[Kk]ey\w*)\s*=\s*['"]AKIA[A-Z0-9]{16}['"]/g,
                    replacement: "$1 $2 = process.env.AWS_ACCESS_KEY_ID || '' // 보안: 환경변수로 이동 필요",
                    description: '하드코딩된 AWS Key를 환경변수로 변경'
                }
            ],
            explanation: 'AWS Access Key가 코드에 노출되면 즉시 AWS 리소스가 위험에 처합니다.'
        }
    ],

    'Google API Key': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /(const|let|var)\s+(\w*[Aa]pi[Kk]ey\w*)\s*=\s*['"]AIza[A-Za-z0-9_-]{35}['"]/g,
                    replacement: "$1 $2 = process.env.GOOGLE_API_KEY || '' // 보안: 환경변수로 이동 필요",
                    description: '하드코딩된 Google API Key를 환경변수로 변경'
                }
            ],
            explanation: 'API Key는 환경변수로 관리하고, Google Cloud Console에서 키 제한을 설정하세요.'
        }
    ],

    'eval() Usage': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /eval\s*\(\s*([^)]+)\s*\)/g,
                    replacement: 'JSON.parse($1) // 보안: eval 대신 JSON.parse 사용',
                    description: 'eval()을 JSON.parse()로 변경 (JSON인 경우)'
                }
            ],
            explanation: 'eval()은 임의의 코드를 실행할 수 있어 매우 위험합니다.'
        }
    ],

    'Disabled SSL Verification': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /rejectUnauthorized\s*:\s*false/g,
                    replacement: 'rejectUnauthorized: true // 보안: SSL 검증 활성화',
                    description: 'SSL 검증 활성화'
                }
            ],
            explanation: 'SSL 인증서 검증을 비활성화하면 MITM 공격에 취약합니다.'
        },
        {
            language: 'python',
            replacements: [
                {
                    pattern: /verify\s*=\s*False/g,
                    replacement: 'verify=True # 보안: SSL 검증 활성화',
                    description: 'SSL 검증 활성화'
                }
            ],
            explanation: 'SSL 인증서 검증을 비활성화하면 MITM 공격에 취약합니다.'
        }
    ],

    'CORS Allow All Origins': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['"]?\*['"]?/g,
                    replacement: "origin: process.env.ALLOWED_ORIGIN || 'https://yourdomain.com' // 보안: origin을 명시적으로 지정",
                    description: 'CORS 와일드카드를 특정 도메인으로 변경'
                }
            ],
            explanation: 'CORS에서 *를 사용하면 모든 도메인에서 요청을 보낼 수 있어 위험합니다.'
        }
    ],

    'JWT No Expiration': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /jwt\.sign\s*\(\s*([^,]+),\s*([^)]+)\s*\)/g,
                    replacement: "jwt.sign($1, $2, { expiresIn: '1h' }) // 보안: JWT 만료 시간 추가",
                    description: 'JWT에 만료 시간 추가'
                }
            ],
            explanation: 'JWT에 만료 시간이 없으면 토큰이 영구적으로 유효하여 위험합니다.'
        }
    ],

    'Path Traversal Risk': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /path\.join\s*\(\s*([^,]+),\s*(req\.[^)]+)\s*\)/g,
                    replacement: "path.join($1, path.basename($2)) // 보안: path.basename으로 경로 정규화",
                    description: 'path.basename()으로 경로 정규화'
                }
            ],
            explanation: '사용자 입력을 파일 경로에 사용하면 ../ 공격으로 임의 파일 접근이 가능합니다.'
        }
    ],

    'document.write': [
        {
            language: 'javascript',
            replacements: [
                {
                    pattern: /document\.write\s*\(\s*([^)]+)\s*\)/g,
                    replacement: '// TODO: DOM API로 변경 필요 (createElement, appendChild 등)\n// document.write($1)',
                    description: 'document.write를 주석 처리하고 TODO 추가'
                }
            ],
            explanation: 'document.write()는 보안상 위험하고 성능도 좋지 않습니다. DOM API를 사용하세요.'
        }
    ]
};

/**
 * 취약점 타입에 대한 자세한 설명
 */
export const VULNERABILITY_EXPLANATIONS: Record<string, string> = {
    'innerHTML Assignment': `
**위험성**:
- XSS(Cross-Site Scripting) 공격에 취약
- 공격자가 악성 스크립트를 삽입할 수 있음

**실제 사례**:
- Myspace Worm (2005): innerHTML을 통해 자동으로 친구 추가

**권장 해결책**:
1. textContent 사용 (HTML 파싱 없음)
2. DOMPurify.sanitize() 사용 (HTML이 꼭 필요한 경우)
3. React/Vue의 자동 이스케이프 활용
`,

    'Template Literal SQL': `
**위험성**:
- SQL Injection 공격에 취약
- 공격자가 임의의 SQL 쿼리 실행 가능

**실제 사례**:
- Equifax 데이터 유출 (2017): 1억 4천만 명의 개인정보 유출

**권장 해결책**:
1. Prepared Statement 사용
2. ORM (Sequelize, TypeORM 등) 사용
3. 입력 검증 및 화이트리스트 필터링
`,

    'Weak Hash (MD5)': `
**위험성**:
- 충돌 공격이 현실적으로 가능
- 레인보우 테이블 공격에 취약

**권장 해결책**:
1. 비밀번호 해싱: bcrypt, argon2
2. 일반 해시: SHA-256 이상
3. HMAC 사용 고려
`,

    'eval() Usage': `
**위험성**:
- 임의의 코드 실행 가능
- XSS와 결합시 치명적

**권장 해결책**:
1. JSON 파싱: JSON.parse() 사용
2. 함수 생성: 특정 목적의 함수 직접 작성
3. 안전한 표현식 평가 라이브러리 사용
`
};
