import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { scanKubernetes } from '../kubernetes.js';

async function tmpYaml(name: string, content: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'iac-k8s-'));
  const file = path.join(dir, name);
  await fs.writeFile(file, content);
  return file;
}

test('R-13: Pod with privileged: true reports an issue', async () => {
  const yaml = `apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: c
      image: nginx
      securityContext:
        privileged: true
`;
  const file = await tmpYaml('pod.yaml', yaml);
  const issues = await scanKubernetes(file);
  assert.ok(issues.length > 0);
});

test('Pod running as root reports an issue', async () => {
  const yaml = `apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: c
      image: nginx
      securityContext:
        runAsUser: 0
`;
  const file = await tmpYaml('pod.yaml', yaml);
  const issues = await scanKubernetes(file);
  assert.ok(issues.length > 0);
});
