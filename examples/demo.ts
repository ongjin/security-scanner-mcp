/**
 * security-scanner-mcp demo
 * Exits non-zero if any expected detection is missing.
 */

import { scanSecrets } from '../src/scanners/secrets.js';
import { scanInjection } from '../src/scanners/injection.js';
import { scanXss } from '../src/scanners/xss.js';
import { scanCrypto } from '../src/scanners/crypto.js';
import { scanAuth } from '../src/scanners/auth.js';
import { scanPath } from '../src/scanners/path.js';

const SAMPLES = {
  secrets: `
    const awsKey = "AKIAJ7VKQ3X5C9Z2N1W4";
    const githubToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
  `,
  injectionTs: `
    const id = req.body.id;
    db.query(\`SELECT * FROM u WHERE id = \${id}\`);
    spawn(req.query.cmd);
  `,
  xssTs: `
    element.innerHTML = userInput;
    document.write(userText);
  `,
  cryptoTs: `
    const h = crypto.createHash('md5');
    const r = Math.random();
    user.password = req.body.password;
  `,
  authTs: `
    jwt.verify(token, secret, { algorithms: ['none'] });
    Access-Control-Allow-Origin: '*'
  `,
  pathTs: `
    const file = req.body.file;
    fs.readFile(file, cb);
    fs.chmod(p, 0o777);
  `,
};

interface Row { scanner: string; count: number; expectedAtLeast: number; }

const rows: Row[] = [
  { scanner: 'secrets',   count: scanSecrets(SAMPLES.secrets, 'typescript').length,           expectedAtLeast: 2 },
  { scanner: 'injection', count: scanInjection(SAMPLES.injectionTs, 'typescript').length,     expectedAtLeast: 2 },
  { scanner: 'xss',       count: scanXss(SAMPLES.xssTs, 'typescript').length,                 expectedAtLeast: 2 },
  { scanner: 'crypto',    count: scanCrypto(SAMPLES.cryptoTs, 'typescript').length,           expectedAtLeast: 3 },
  { scanner: 'auth',      count: scanAuth(SAMPLES.authTs, 'typescript').length,               expectedAtLeast: 2 },
  { scanner: 'path',      count: scanPath(SAMPLES.pathTs, 'typescript').length,               expectedAtLeast: 2 },
];

console.log('security-scanner-mcp demo');
console.log('-'.repeat(50));
console.log('scanner    count  expected (>=)');
for (const r of rows) {
  const pad = (s: string, n: number) => s + ' '.repeat(Math.max(0, n - s.length));
  console.log(`${pad(r.scanner, 11)}${pad(String(r.count), 7)}${r.expectedAtLeast}`);
}
console.log('-'.repeat(50));

const missing = rows.filter(r => r.count < r.expectedAtLeast);
if (missing.length > 0) {
  console.error('\nFAIL: expected detections missing:');
  for (const m of missing) console.error(`  ${m.scanner}: got ${m.count}, expected >= ${m.expectedAtLeast}`);
  process.exit(1);
}
console.log('\nOK: all expected detections present.');
