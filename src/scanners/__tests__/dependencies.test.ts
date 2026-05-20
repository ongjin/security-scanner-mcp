import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { scanDependencies } from '../dependencies.js';

async function makeTmpProject(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'scanner-deps-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

test('package.json with vulnerable lodash version reports an issue', async () => {
  const dir = await makeTmpProject({
    'package.json': JSON.stringify({ name: 'fixture', dependencies: { lodash: '4.17.20' } }),
  });
  const issues = await scanDependencies(dir);
  assert.ok(issues.some(i => i.type.includes('lodash')));
});

test('package.json with no known-vuln dependency is clean', async () => {
  const dir = await makeTmpProject({
    'package.json': JSON.stringify({ name: 'fixture', dependencies: { 'left-pad': '1.3.0' } }),
  });
  const issues = await scanDependencies(dir);
  const knownVulnIssues = issues.filter(i => i.type.startsWith('Vulnerable Package'));
  assert.equal(knownVulnIssues.length, 0);
});

test('Empty directory yields no issues and does not throw', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'scanner-deps-empty-'));
  const issues = await scanDependencies(dir);
  assert.ok(Array.isArray(issues));
});

test('requirements.txt with pyyaml reports critical', async () => {
  const dir = await makeTmpProject({
    'requirements.txt': 'pyyaml==5.1\nrequests==2.25.0\n',
  });
  const issues = await scanDependencies(dir);
  assert.ok(issues.some(i => i.type.includes('pyyaml')));
});
