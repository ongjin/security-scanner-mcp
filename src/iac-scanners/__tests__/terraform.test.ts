import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { scanTerraform } from '../terraform.js';

async function tmpTf(content: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'iac-tf-'));
  const file = path.join(dir, 'main.tf');
  await fs.writeFile(file, content);
  return file;
}

test('R-14: Security group open to 0.0.0.0/0 reports an issue', async () => {
  const tf = `
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
  const file = await tmpTf(tf);
  const issues = await scanTerraform(file);
  assert.ok(issues.length > 0);
});

test('S3 bucket with public ACL reports an issue', async () => {
  const tf = `
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`;
  const file = await tmpTf(tf);
  const issues = await scanTerraform(file);
  assert.ok(issues.length > 0);
});
