import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { compileRules, ConfigError, loadRules } from '../src/rules.mjs';
import { scanContent, scanPath } from '../src/scanner.mjs';
import { fake, rand, BASE64, HEX } from '../support/fixtures.mjs';

const rules = loadRules();
const ids = (text) => scanContent(text, { file: 'demo.txt', rules }).map((f) => f.ruleId);

// Each row: the rule, a line it must report, and a similar line it must not.
const cases = [
  ['private-key', 'RSA block', fake.privateKey('RSA '), '-----BEGIN RSA PRIVATE KEY----- (header quoted in docs, no key material)'],
  ['private-key', 'EC block', fake.privateKey('EC '), `-----BEGIN EC PRIVATE KEY-----\n${'A'.repeat(64)}`],
  ['private-key', 'OpenSSH block', fake.privateKey('OPENSSH '), fake.privateKey('OPENSSH ').replace('PRIVATE', 'PUBLIC')],
  ['private-key', 'PGP block', fake.pgpKey(), '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n' + rand(64, 3, BASE64)],
  ['aws-access-key-id', 'access key id', `aws_access_key_id = ${fake.awsKeyId()}`, `id = AK${'IA'}IOSFODNN7EXAMPLE`],
  ['aws-secret-access-key', 'secret key', `AWS_SECRET_ACCESS_KEY="${fake.awsSecret()}"`, `AWS_SECRET_ACCESS_KEY="${'abcd'.repeat(10)}"`],
  ['github-token', 'ghp_ token', `token: ${fake.github('ghp')}`, `ghp_${'x'.repeat(36)}`],
  ['github-token', 'gho_ token', fake.github('gho'), `gho_${rand(20)}`],
  ['github-token', 'ghs_ token', fake.github('ghs'), `notghs_${rand(36)}`],
  ['github-fine-grained-token', 'github_pat_', fake.githubFine(), `github${'_pat_'}${rand(10)}`],
  ['stripe-live-key', 'sk_live_', fake.stripe('sk', 'live'), fake.stripe('sk', 'test')],
  ['stripe-restricted-key', 'rk_live_', fake.stripe('rk', 'live'), fake.stripe('rk', 'test')],
  ['slack-token', 'xoxb-', fake.slackBot(), 'xoxb-not-a-token'],
  ['slack-webhook', 'webhook URL', `url: ${fake.slackWebhook()}`, 'https://hooks.slack.com/services/'],
  ['google-api-key', 'Google key', `key=${fake.google()}`, `A${'Iza'}${rand(20)}`],
  ['twilio-api-key', 'SK sid', fake.twilioKey(), `SK${rand(32, 1, 'ghijklmnop')}`],
  ['twilio-auth-token', 'auth token', `TWILIO_AUTH_TOKEN=${fake.twilioToken()}`, `TWILIO_AUTH_TOKEN=${'0'.repeat(32)}`],
  ['sendgrid-api-key', 'SG. key', fake.sendgrid(), `S${'G.'}${'a'.repeat(22)}.${'b'.repeat(43)}`],
  ['jwt', 'signed token', `Authorization: Bearer ${fake.jwt()}`, `eyJ${rand(20)}.eyJ${rand(20)}.${rand(30)}`],
  ['database-url', 'postgres URL', `postgres://app:${fake.password()}@db.internal:5432/app`, 'postgres://user:password@localhost:5432/app'],
  ['database-url', 'mongodb+srv URL', `mongodb+srv://svc:${fake.password(21)}@cluster0.example.net/db`, 'mongodb://localhost:27017/db'],
  ['generic-assignment', 'quoted password', `const dbPassword = "${fake.password()}";`, 'const dbPassword = process.env.DB_PASSWORD;'],
  ['generic-assignment', 'KEY=value line', `API_SECRET=${fake.password(15)}`, 'API_SECRET=changeme_please'],
  ['generic-assignment', 'JSON field', `{"client_secret": "${fake.password(16)}"}`, '{"client_secret": "${CLIENT_SECRET}"}'],
];

describe('default rules: true and false positives', () => {
  for (const [rule, label, positive, negative] of cases) {
    test(`${rule} reports a ${label}`, () => {
      assert.ok(ids(positive).includes(rule), `expected ${rule} in ${JSON.stringify(ids(positive))}`);
    });
    test(`${rule} ignores a near miss for ${label}`, () => {
      assert.ok(!ids(negative).includes(rule), `did not expect ${rule}`);
    });
  }
});

describe('rule behaviour', () => {
  test('every bundled rule has a positive case above', () => {
    const covered = new Set(cases.map(([id]) => id));
    covered.add('dotenv-file');
    for (const rule of rules) assert.ok(covered.has(rule.id), `${rule.id} has no test case`);
  });

  test('dotenv-file flags .env and .env.production but not .env.example', () => {
    assert.deepEqual(scanPath('.env', rules).map((f) => f.ruleId), ['dotenv-file']);
    assert.deepEqual(scanPath('config/.env.production', rules).map((f) => f.ruleId), ['dotenv-file']);
    assert.deepEqual(scanPath('.env.example', rules), []);
    assert.deepEqual(scanPath('docs/env.md', rules), []);
  });

  test('AWS secret key is linked to the access key id in the same file', () => {
    const text = `[default]\naws_access_key_id = ${fake.awsKeyId()}\naws_secret_access_key = ${fake.awsSecret()}\n`;
    const findings = scanContent(text, { rules });
    const secret = findings.find((f) => f.ruleId === 'aws-secret-access-key');
    assert.ok(secret);
    assert.deepEqual(secret.related, [{ ruleId: 'aws-access-key-id', line: 2, column: 21 }]);
  });

  test('a generic assignment wrapping a specific token is reported once, as the specific rule', () => {
    assert.deepEqual(ids(`GITHUB_TOKEN="${fake.github()}"`), ['github-token']);
  });

  test('a JWT whose header is not JSON is not reported', () => {
    const bogus = `eyJ${rand(30, 7, BASE64.replace(/[+/]/g, 'x'))}.eyJ${rand(30, 8)}.${rand(40, 9)}`;
    assert.deepEqual(ids(bogus), []);
  });

  test('positions are 1-based line and column of the value', () => {
    const [finding] = scanContent(`first\n  key: ${fake.github()}\n`, { rules });
    assert.equal(finding.line, 2);
    assert.equal(finding.column, 8);
    assert.equal(finding.endColumn, 8 + 40);
  });

  test('findings never serialise the raw value', () => {
    const token = fake.github();
    const [finding] = scanContent(token, { rules });
    assert.equal(finding.secret, token);
    assert.ok(!JSON.stringify(finding).includes(token));
    assert.match(finding.match, /^ghp_\*+$/);
  });

  test('twilio auth token needs a twilio name beside it', () => {
    assert.deepEqual(ids(`checksum = "${rand(32, 4, HEX)}"`), []);
  });
});

describe('rules loader', () => {
  test('rejects a file without a rules array', () => {
    assert.throws(() => compileRules({}), ConfigError);
  });

  test('rejects duplicate ids', () => {
    const rule = { id: 'dup', pattern: 'x' };
    assert.throws(() => compileRules({ rules: [rule, rule] }), /duplicate id/);
  });

  test('rejects an invalid regular expression', () => {
    assert.throws(() => compileRules({ rules: [{ id: 'bad', pattern: '(' }] }), /invalid regular expression/);
  });

  test('rejects an unknown severity and validator', () => {
    assert.throws(() => compileRules({ rules: [{ id: 'a', pattern: 'x', severity: 'urgent' }] }), /severity/);
    assert.throws(() => compileRules({ rules: [{ id: 'a', pattern: 'x', validate: 'nope' }] }), /validator/);
  });

  test('custom rules work end to end', () => {
    const custom = compileRules({ rules: [{ id: 'corvane-key', pattern: '(CV-[0-9a-f]{24})', minEntropy: 2 }] });
    const findings = scanContent(`k = CV-${rand(24, 2, HEX)}`, { rules: custom });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].ruleId, 'corvane-key');
  });

  test('loadRules reports a missing file as a configuration error', () => {
    assert.throws(() => loadRules('/nonexistent/rules.json'), ConfigError);
  });
});

describe('generic assignment false positives', () => {
  test('a string with escape sequences is not taken for a password', () => {
    assert.deepEqual(ids(`const files = { '.secretscanignore': 'fixtures/\\n' };`), []);
  });

  test('a short value is not reported', () => {
    assert.deepEqual(ids('password = "Ab1!x"'), []);
  });

  test('an unquoted value inside code is not reported', () => {
    assert.deepEqual(ids('  const token = getToken(request);'), []);
  });

  test('an unquoted KEY=value line with a trailing comment is reported', () => {
    assert.deepEqual(ids(`SMTP_PASSWORD=${fake.password(31)}  # rotate quarterly`), ['generic-assignment']);
  });
});
