#!/usr/bin/env node
// Builds a small throwaway project for Corvane Supply Co., a fictional distributor used
// in this demo, with a few planted credentials, then scans it. The values are made at
// run time and never written into this repository.
//
//   node examples/demo.mjs                 text report
//   node examples/demo.mjs --format json   any secret-scan option is passed through
import { tmpdir } from 'node:os';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { run } from '../src/cli.mjs';
import { fake } from '../support/fixtures.mjs';

const dir = mkdtempSync(join(tmpdir(), 'corvane-demo-'));
const files = {
  '.gitignore': 'node_modules/\n',
  '.env': 'PORT=8080\n',
  '.env.example': 'PORT=\nDATABASE_URL=\n',
  'src/orders.js': [
    "import Stripe from './stripe.js';",
    '',
    `const stripe = new Stripe('${fake.stripe()}');`,
    '',
  ].join('\n'),
  'deploy/credentials': [
    '[default]',
    `aws_access_key_id = ${fake.awsKeyId()}`,
    `aws_secret_access_key = ${fake.awsSecret()}`,
    '',
  ].join('\n'),
  'config/database.yml': `url: postgres://orders:${fake.password()}@db.corvane.example:5432/orders\n`,
  'docs/setup.md': [
    'Point the client at a test key:',
    '',
    `    API_KEY=${fake.google(99)}   # secret-scan:allow documented sample`,
    '',
  ].join('\n'),
};
for (const [name, content] of Object.entries(files)) {
  mkdirSync(join(dir, name, '..'), { recursive: true });
  writeFileSync(join(dir, name), content);
}

const code = await run(process.argv.slice(2), { cwd: dir });
rmSync(dir, { recursive: true, force: true });
process.exitCode = code;
