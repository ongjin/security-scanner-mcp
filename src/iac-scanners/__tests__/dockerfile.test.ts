import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { scanDockerfile } from '../dockerfile.js';

async function tmpFile(name: string, content: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'iac-docker-'));
  const file = path.join(dir, name);
  await fs.writeFile(file, content);
  return file;
}

test('R-12: Dockerfile with USER root reports an issue', async () => {
  const file = await tmpFile('Dockerfile', `FROM node:20\nUSER root\nCMD ["node", "app.js"]\n`);
  const issues = await scanDockerfile(file);
  assert.ok(issues.length > 0);
});

test('Dockerfile with :latest tag reports an issue', async () => {
  const file = await tmpFile('Dockerfile', `FROM node:latest\n`);
  const issues = await scanDockerfile(file);
  assert.ok(issues.length > 0);
});

test('Minimal hardened Dockerfile produces no critical issues', async () => {
  const file = await tmpFile('Dockerfile', `FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD ["true"]\n`);
  const issues = await scanDockerfile(file);
  assert.equal(issues.filter(i => i.severity === 'critical').length, 0);
});
