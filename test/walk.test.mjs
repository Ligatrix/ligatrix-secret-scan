import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../src/scan.mjs';
import { collectFiles, hasBinaryExtension, looksBinary } from '../src/walk.mjs';
import { fake, tempTree } from '../support/fixtures.mjs';

const relFiles = async (dir, options = {}) =>
  (await collectFiles(['.'], { root: dir, ...options })).files.map((f) => f.rel).sort();

test('the walk honours .gitignore, nested ignore files and skips .git', async (t) => {
  const tree = tempTree({
    '.gitignore': 'dist/\n*.log\n',
    'src/app.js': 'ok',
    'src/debug.log': 'x',
    'dist/bundle.js': 'x',
    'packages/api/.gitignore': 'local.json\n',
    'packages/api/local.json': 'x',
    'packages/web/local.json': 'x',
    '.git/config': 'x',
  });
  t.after(tree.cleanup);
  assert.deepEqual(await relFiles(tree.dir), [
    '.gitignore',
    'packages/api/.gitignore',
    'packages/web/local.json',
    'src/app.js',
  ]);
});

test('--no-gitignore walks ignored files but still skips .git', async (t) => {
  const tree = tempTree({ '.gitignore': '*.log\n', 'a.log': 'x', '.git/HEAD': 'x' });
  t.after(tree.cleanup);
  assert.deepEqual(await relFiles(tree.dir, { gitignore: false }), ['.gitignore', 'a.log']);
});

test('scanning a sub-directory applies ignore files from the repository top', async (t) => {
  const tree = tempTree({ '.git/HEAD': 'x', '.gitignore': 'build-out/\n', 'pkg/build-out/a.js': 'x', 'pkg/b.js': 'x' });
  t.after(tree.cleanup);
  const { files } = await collectFiles(['pkg'], { root: tree.dir });
  assert.deepEqual(files.map((f) => f.rel), ['pkg/b.js']);
});

test('symbolic links are not followed', async (t) => {
  const tree = tempTree({ 'real/a.txt': 'x' });
  t.after(tree.cleanup);
  symlinkSync(join(tree.dir, 'real'), join(tree.dir, 'link'));
  assert.deepEqual(await relFiles(tree.dir), ['real/a.txt']);
});

test('binary files are detected by NUL byte and by extension', () => {
  assert.ok(looksBinary(Buffer.from([0x41, 0x00, 0x42])));
  assert.ok(!looksBinary(Buffer.from('plain text')));
  assert.ok(hasBinaryExtension('logo.PNG'));
  assert.ok(!hasBinaryExtension('notes.md'));
});

test('binary and oversized files are skipped and listed with a reason', async (t) => {
  const token = fake.github();
  const tree = tempTree({ 'image.png': token, 'big.txt': `${'x'.repeat(2000)}\n${token}`, 'small.txt': 'hello' });
  t.after(tree.cleanup);
  writeFileSync(join(tree.dir, 'blob.dat'), Buffer.concat([Buffer.from(token), Buffer.from([0])]));
  const result = await scan({ cwd: tree.dir, maxSize: 1000 });
  assert.equal(result.findings.length, 0);
  assert.equal(result.filesScanned, 1);
  assert.deepEqual(
    result.filesSkipped.map((s) => `${s.file}:${s.reason}`).sort(),
    ['big.txt:too large', 'blob.dat:binary', 'image.png:binary'],
  );
});

test('a file passed explicitly is scanned even when ignored', async (t) => {
  const tree = tempTree({ '.gitignore': 'secret.txt\n', 'secret.txt': `t=${fake.github()}` });
  t.after(tree.cleanup);
  const result = await scan({ cwd: tree.dir, paths: ['secret.txt'] });
  assert.equal(result.findings.length, 1);
});

test('a gitignored .env file is not reported; a tracked one is', async (t) => {
  const ignored = tempTree({ '.gitignore': '.env\n', '.env': 'A=1\n' });
  const tracked = tempTree({ '.env': 'A=1\n', '.env.example': 'A=\n' });
  t.after(() => { ignored.cleanup(); tracked.cleanup(); });
  assert.equal((await scan({ cwd: ignored.dir })).findings.length, 0);
  const findings = (await scan({ cwd: tracked.dir })).findings;
  assert.deepEqual(findings.map((f) => `${f.file}:${f.ruleId}`), ['.env:dotenv-file']);
});

test('the scan reports file paths relative to the working directory', async (t) => {
  const tree = tempTree({});
  t.after(tree.cleanup);
  mkdirSync(join(tree.dir, 'config'));
  writeFileSync(join(tree.dir, 'config', 'app.yml'), `stripe: ${fake.stripe()}\n`);
  const [finding] = (await scan({ cwd: tree.dir })).findings;
  assert.equal(finding.file, 'config/app.yml');
});
