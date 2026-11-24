import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatJson, formatSarif, formatText, VERSION } from '../src/format.mjs';
import { loadRules } from '../src/rules.mjs';
import { scanContent } from '../src/scanner.mjs';
import { fake } from '../support/fixtures.mjs';

const rules = loadRules();
const token = fake.github();
const awsText = `aws_access_key_id = ${fake.awsKeyId()}\naws_secret_access_key = ${fake.awsSecret()}\n`;

function resultFor(text, file = 'src/config.js') {
  return {
    findings: scanContent(text, { file, rules }),
    filesScanned: 3,
    filesSkipped: [{ file: 'logo.png', reason: 'binary' }],
    suppressed: 0,
    rules,
  };
}

test('text output names file:line:column, rule, masked value and fingerprint', () => {
  const out = formatText(resultFor(`\nconst t = "${token}";\n`));
  assert.match(out, /^src\/config\.js:2:12 {2}HIGH {2}GitHub token \(github-token\)$/m);
  assert.match(out, /value {8}ghp_\*{16}/);
  assert.match(out, /fingerprint {2}[0-9a-f]{32}/);
  assert.match(out, /1 finding in 1 file \(scanned 3 files, skipped 1\)\./);
  assert.ok(!out.includes(token));
});

test('text output for a clean scan says so', () => {
  assert.equal(formatText(resultFor('nothing here')), 'No secrets found (scanned 3 files, skipped 1).\n');
});

test('text output shows a paired AWS key', () => {
  assert.match(formatText(resultFor(awsText)), /pairs with {3}aws-access-key-id at line 1/);
});

test('json output is parseable, masked and complete', () => {
  const report = JSON.parse(formatJson(resultFor(token)));
  assert.equal(report.tool, 'secret-scan');
  assert.equal(report.version, VERSION);
  assert.equal(report.filesScanned, 3);
  assert.equal(report.findings.length, 1);
  const [f] = report.findings;
  assert.deepEqual(Object.keys(f).sort(), [
    'column', 'endColumn', 'endLine', 'entropy', 'file', 'fingerprint', 'line', 'match', 'ruleId', 'ruleName', 'severity',
  ]);
  assert.ok(!JSON.stringify(report).includes(token));
});

test('sarif output has the 2.1.0 shape code scanning expects', () => {
  const log = JSON.parse(formatSarif(resultFor(awsText, 'deploy/credentials')));
  assert.equal(log.version, '2.1.0');
  assert.match(log.$schema, /sarif-2\.1\.0/);
  assert.equal(log.runs.length, 1);
  const [run] = log.runs;
  assert.equal(run.tool.driver.name, 'secret-scan');
  assert.equal(run.tool.driver.rules.length, rules.length);
  for (const rule of run.tool.driver.rules) {
    assert.ok(rule.id && rule.name && rule.shortDescription.text && rule.fullDescription.text);
    assert.ok(['error', 'warning', 'note'].includes(rule.defaultConfiguration.level));
    assert.match(rule.properties['security-severity'], /^\d+\.\d$/);
  }
  assert.equal(run.results.length, 2);
  for (const result of run.results) {
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
    assert.ok(result.message.text.length > 0);
    const { artifactLocation, region } = result.locations[0].physicalLocation;
    assert.equal(artifactLocation.uri, 'deploy/credentials');
    assert.equal(artifactLocation.uriBaseId, '%SRCROOT%');
    assert.ok(region.startLine >= 1 && region.startColumn >= 1 && region.endColumn > region.startColumn);
    assert.match(result.partialFingerprints['secretFingerprint/v1'], /^[0-9a-f]{32}$/);
  }
  const paired = run.results.find((r) => r.ruleId === 'aws-secret-access-key');
  assert.equal(paired.relatedLocations[0].physicalLocation.region.startLine, 1);
});

test('sarif uris are percent-encoded and severities map to levels', () => {
  const log = JSON.parse(formatSarif(resultFor(fake.slackWebhook(), 'docs/team notes.md')));
  const [result] = log.runs[0].results;
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'docs/team%20notes.md');
  assert.equal(result.level, 'warning');
});

test('sarif for a clean scan still lists the rules with an empty result set', () => {
  const log = JSON.parse(formatSarif(resultFor('clean')));
  assert.deepEqual(log.runs[0].results, []);
  assert.ok(log.runs[0].tool.driver.rules.length > 10);
});
