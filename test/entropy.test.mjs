import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy } from '../src/entropy.mjs';
import { compileRules } from '../src/rules.mjs';
import { scanContent } from '../src/scanner.mjs';
import { rand, HEX } from '../support/fixtures.mjs';

test('entropy of an empty or non-string value is 0', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.equal(shannonEntropy(undefined), 0);
});

test('entropy of a repeated character is 0', () => {
  assert.equal(shannonEntropy('aaaaaaaa'), 0);
});

test('entropy of two equally frequent characters is 1 bit', () => {
  assert.equal(shannonEntropy('abababab'), 1);
});

test('entropy of 16 distinct characters is 4 bits', () => {
  assert.equal(shannonEntropy('0123456789abcdef'), 4);
});

test('random tokens score far above words', () => {
  assert.ok(shannonEntropy(rand(40)) > 4.5);
  assert.ok(shannonEntropy('passwordpassword') < 3);
});

test('minEntropy decides whether a shaped match is reported', () => {
  const [rule] = compileRules({ rules: [{ id: 'hex-key', pattern: 'key=([0-9a-f]{32})', minEntropy: 3.2 }] });
  assert.equal(scanContent(`key=${'ab'.repeat(16)}`, { rules: [rule] }).length, 0);
  assert.equal(scanContent(`key=${rand(32, 5, HEX)}`, { rules: [rule] }).length, 1);
});

test('the reported entropy is rounded to two decimals', () => {
  const [rule] = compileRules({ rules: [{ id: 'any', pattern: '(\\S{12,})' }] });
  const [finding] = scanContent(rand(30, 2), { rules: [rule] });
  assert.equal(finding.entropy, Math.round(shannonEntropy(finding.secret) * 100) / 100);
});
