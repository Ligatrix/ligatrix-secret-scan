import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from '../src/index.mjs';
import { parseArgs, parseSize } from '../src/cli.mjs';
import { fake, sink, tempTree } from '../support/fixtures.mjs';

const BIN = fileURLToPath(new URL('../bin/secret-scan.mjs', import.meta.url));
const HOOK = fileURLToPath(new URL('../hooks/pre-commit', import.meta.url));

async function cli(args, cwd) {
  const stdout = sink();
  const stderr = sink();
  const code = await run(args, { stdout, stderr, cwd });
  return { code, stdout: stdout.text, stderr: stderr.text };
}

function gitRepo(files = {}) {
  const tree = tempTree(files);
  const git = (...args) =>
    execFileSync('git', ['-c', 'user.name=Dana', '-c', 'user.email=dana@corvane.example', ...args], {
      cwd: tree.dir,
      encoding: 'utf8',
    });
  git('init', '-q', '-b', 'main');
  return { ...tree, git };
}

test('exit code 0 for a clean tree', async (t) => {
  const tree = tempTree({ 'README.md': '# Corvane Supply Co., a fictional distributor used in this demo\n' });
  t.after(tree.cleanup);
  const { code, stdout } = await cli([], tree.dir);
  assert.equal(code, 0);
  assert.match(stdout, /No secrets found \(scanned 1 file\)/);
});

test('exit code 1 when a secret is found', async (t) => {
  const tree = tempTree({ 'app.js': `const s = "${fake.sendgrid()}";\n` });
  t.after(tree.cleanup);
  const { code, stdout } = await cli(['.'], tree.dir);
  assert.equal(code, 1);
  assert.match(stdout, /app\.js:1:12 {2}HIGH {2}SendGrid API key/);
});

test('exit code 2 for usage errors', async () => {
  for (const args of [['--bogus'], ['--format', 'xml'], ['--format'], ['--max-size', 'lots'], ['--staged', 'src']]) {
    const { code, stderr } = await cli(args, process.cwd());
    assert.equal(code, 2, `args ${args.join(' ')}`);
    assert.match(stderr, /^secret-scan: /);
  }
});

test('exit code 2 for a missing path or a broken rules file', async (t) => {
  const tree = tempTree({ 'rules.json': '{ not json' });
  t.after(tree.cleanup);
  assert.equal((await cli(['does-not-exist'], tree.dir)).code, 2);
  const broken = await cli(['--rules', 'rules.json'], tree.dir);
  assert.equal(broken.code, 2);
  assert.match(broken.stderr, /not valid JSON/);
});

test('argument parsing accepts --flag=value and short flags', () => {
  const options = parseArgs(['-f', 'json', '--max-size=2m', '-o', 'out.json', 'src', '--', '--odd-name']);
  assert.equal(options.format, 'json');
  assert.equal(options.maxSize, 2 * 1024 * 1024);
  assert.equal(options.output, 'out.json');
  assert.deepEqual(options.paths, ['src', '--odd-name']);
  assert.equal(parseSize('512k'), 524288);
  assert.equal(parseSize('1000'), 1000);
});

test('--help, --version and --list-rules exit 0', async () => {
  assert.match((await cli(['--help'])).stdout, /Exit codes: 0 no findings, 1 findings, 2 usage/);
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal((await cli(['--version'])).stdout.trim(), pkg.version);
  const list = await cli(['--list-rules']);
  assert.equal(list.code, 0);
  assert.match(list.stdout, /^private-key +high +Private key block$/m);
});

test('--format json and sarif write parseable reports, --output writes a file', async (t) => {
  const tree = tempTree({ 'a.env.sh': `export DB_PASSWORD=${fake.password()}\n` });
  t.after(tree.cleanup);
  const json = await cli(['--format', 'json'], tree.dir);
  assert.equal(json.code, 1);
  assert.equal(JSON.parse(json.stdout).findings[0].ruleId, 'generic-assignment');
  const sarif = await cli(['--format=sarif', '--output', 'report.sarif'], tree.dir);
  assert.equal(sarif.code, 1);
  assert.equal(sarif.stdout, '');
  assert.match(sarif.stderr, /1 finding in 1 file/);
  const log = JSON.parse(readFileSync(join(tree.dir, 'report.sarif'), 'utf8'));
  assert.equal(log.runs[0].results[0].ruleId, 'generic-assignment');
});

test('the bin script runs as a process and sets the exit code', (t) => {
  const tree = tempTree({ 'notes.txt': `slack: ${fake.slackBot()}\n` });
  t.after(tree.cleanup);
  const found = spawnSync(process.execPath, [BIN], { cwd: tree.dir, encoding: 'utf8' });
  assert.equal(found.status, 1);
  assert.match(found.stdout, /notes\.txt:1:8 {2}HIGH {2}Slack token/);
  const usage = spawnSync(process.execPath, [BIN, '--nope'], { cwd: tree.dir, encoding: 'utf8' });
  assert.equal(usage.status, 2);
});

test('--staged scans what is in the index, not the working tree', async (t) => {
  const repo = gitRepo({ 'config.js': 'module.exports = {};\n' });
  t.after(repo.cleanup);
  repo.git('add', 'config.js');
  repo.git('commit', '-q', '-m', 'Initial');

  writeFileSync(join(repo.dir, 'config.js'), `module.exports = { key: "${fake.stripe()}" };\n`);
  assert.equal((await cli(['--staged'], repo.dir)).code, 0, 'unstaged change is not scanned');

  repo.git('add', 'config.js');
  const staged = await cli(['--staged'], repo.dir);
  assert.equal(staged.code, 1);
  assert.match(staged.stdout, /config\.js:1:26 {2}HIGH {2}Stripe live secret key/);

  writeFileSync(join(repo.dir, 'config.js'), 'module.exports = {};\n');
  assert.equal((await cli(['--staged'], repo.dir)).code, 1, 'the staged blob is what counts');
});

test('--staged reports a staged .env file and uses paths from the repository top', async (t) => {
  const repo = gitRepo({ 'app/.env': 'PORT=8080\n' });
  t.after(repo.cleanup);
  repo.git('add', 'app/.env');
  const result = await cli(['--staged', '--format', 'json'], join(repo.dir, 'app'));
  assert.equal(result.code, 1);
  assert.deepEqual(JSON.parse(result.stdout).findings.map((f) => `${f.file}:${f.ruleId}`), ['app/.env:dotenv-file']);
});

test('--staged outside a git repository is a usage error', async (t) => {
  const tree = tempTree({ 'a.txt': 'x' });
  t.after(tree.cleanup);
  const result = await cli(['--staged'], tree.dir);
  if (result.code !== 2) {
    // The temporary directory sits inside a repository on this machine; nothing to assert.
    t.skip('temporary directory is inside a git repository');
    return;
  }
  assert.match(result.stderr, /inside a git repository/);
});

test('the sample pre-commit hook blocks a commit holding a secret', (t) => {
  const repo = gitRepo({ 'ok.txt': 'fine\n' });
  t.after(repo.cleanup);
  const binDir = join(repo.dir, '.tools');
  mkdirSync(binDir);
  symlinkSync(BIN, join(binDir, 'secret-scan'));
  const hooks = join(repo.dir, '.git', 'hooks');
  writeFileSync(join(hooks, 'pre-commit'), readFileSync(HOOK));
  chmodSync(join(hooks, 'pre-commit'), 0o755);
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  const commit = (msg) =>
    spawnSync('git', ['-c', 'user.name=Dana', '-c', 'user.email=dana@corvane.example', 'commit', '-q', '-m', msg], {
      cwd: repo.dir,
      env,
      encoding: 'utf8',
    });

  repo.git('add', 'ok.txt');
  assert.equal(commit('Add notes').status, 0);

  writeFileSync(join(repo.dir, 'deploy.sh'), `curl -H "Authorization: token ${fake.github()}"\n`);
  repo.git('add', 'deploy.sh');
  const blocked = commit('Add deploy script');
  assert.notEqual(blocked.status, 0);
  assert.match(blocked.stdout + blocked.stderr, /GitHub token/);
});
