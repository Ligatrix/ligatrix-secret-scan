import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAllowlist } from '../src/allowlist.mjs';
import { ConfigError, loadRules } from '../src/rules.mjs';
import { scan } from '../src/scan.mjs';
import { fingerprint, scanContent } from '../src/scanner.mjs';
import { fake, tempTree } from '../support/fixtures.mjs';

const rules = loadRules();

test('an inline secret-scan:allow comment suppresses a finding on its line', () => {
  const text = `const key = "${fake.google()}"; // secret-scan:allow documented sample\n`;
  assert.equal(scanContent(text, { rules }).length, 0);
});

test('secret-scan:allow-next-line suppresses the following line only', () => {
  const text = `# secret-scan:allow-next-line\nA=${fake.github(undefined, 1)}\nB=${fake.github(undefined, 2)}\n`;
  const findings = scanContent(text, { rules });
  assert.deepEqual(findings.map((f) => f.line), [3]);
});

test('an inline allow on a private key header covers the block', () => {
  const text = fake.privateKey().replace('-----\n', '----- secret-scan:allow\n');
  assert.equal(scanContent(text, { rules }).length, 0);
});

test('the fingerprint depends on rule and value, not position', () => {
  const token = fake.github();
  const a = scanContent(token, { rules })[0];
  const b = scanContent(`\n\n   ${token}`, { rules, file: 'other.txt' })[0];
  assert.equal(a.fingerprint, b.fingerprint);
  assert.equal(a.fingerprint, fingerprint('github-token', token));
  assert.match(a.fingerprint, /^[0-9a-f]{32}$/);
});

test('allowlist entries: fingerprints, globs, negation and rule switches', () => {
  const token = fake.github();
  const list = parseAllowlist(
    [
      '# known test values',
      `fingerprint:${fingerprint('github-token', token)}`,
      'docs/**',
      '!docs/live.md',
      'rule:jwt',
      'rule:generic-assignment test/**',
    ].join('\n'),
  );
  const finding = (ruleId, file, secret = 'x') => ({ ruleId, file, fingerprint: fingerprint(ruleId, secret) });
  assert.ok(list.allows(finding('github-token', 'src/a.js', token)));
  assert.ok(!list.allows(finding('github-token', 'src/a.js', `${token}x`)));
  assert.ok(list.allows(finding('slack-token', 'docs/guide.md')));
  assert.ok(!list.allows(finding('slack-token', 'docs/live.md')));
  assert.ok(list.allows(finding('jwt', 'anywhere.js')));
  assert.ok(list.allows(finding('generic-assignment', 'test/a.test.js')));
  assert.ok(!list.allows(finding('generic-assignment', 'src/a.js')));
});

test('a malformed fingerprint line is a configuration error', () => {
  assert.throws(() => parseAllowlist('fingerprint:xyz'), ConfigError);
  assert.throws(() => parseAllowlist('rule:'), ConfigError);
});

test('.secretscanignore at the root is applied and counted as suppressed', async (t) => {
  const tree = tempTree({
    '.secretscanignore': 'fixtures/\n',
    'fixtures/sample.txt': `token ${fake.github()}`,
    'src/app.js': `const k = "${fake.stripe()}";`,
  });
  t.after(tree.cleanup);
  const result = await scan({ cwd: tree.dir });
  assert.deepEqual(result.findings.map((f) => f.file), ['src/app.js']);
  assert.equal(result.suppressed, 1);
});

test('an explicit --ignore-file must exist', async (t) => {
  const tree = tempTree({ 'a.txt': 'x' });
  t.after(tree.cleanup);
  await assert.rejects(scan({ cwd: tree.dir, ignoreFile: 'missing-allowlist' }), ConfigError);
});
