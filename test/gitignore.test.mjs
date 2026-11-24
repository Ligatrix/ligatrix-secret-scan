import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IgnoreMatcher, compilePattern } from '../src/gitignore.mjs';

const matcher = (text, base) => new IgnoreMatcher().add(text, base);

test('blank lines and comments are not patterns', () => {
  assert.equal(compilePattern(''), null);
  assert.equal(compilePattern('# comment'), null);
  assert.equal(compilePattern('   '), null);
});

test('an escaped hash is a literal file name', () => {
  assert.ok(matcher('\\#notes').ignores('#notes'));
});

test('a name without a slash matches at any depth', () => {
  const m = matcher('*.log');
  assert.ok(m.ignores('app.log'));
  assert.ok(m.ignores('logs/deep/app.log'));
  assert.ok(!m.ignores('app.log.txt'));
});

test('a leading slash anchors to the ignore file directory', () => {
  const m = matcher('/build');
  assert.ok(m.ignores('build', true));
  assert.ok(!m.ignores('src/build', true));
});

test('a pattern with a middle slash is anchored', () => {
  const m = matcher('docs/*.md');
  assert.ok(m.ignores('docs/a.md'));
  assert.ok(!m.ignores('sub/docs/a.md'));
  assert.ok(!m.ignores('docs/deep/a.md'));
});

test('a trailing slash matches directories only', () => {
  const m = matcher('cache/');
  assert.ok(m.ignores('cache', true));
  assert.ok(!m.ignores('cache', false));
  assert.ok(m.ignores('cache/file.txt'));
});

test('negation re-includes a file', () => {
  const m = matcher('*.env\n!example.env');
  assert.ok(m.ignores('prod.env'));
  assert.ok(!m.ignores('example.env'));
});

test('negation cannot re-include a file inside an ignored directory', () => {
  const m = matcher('secrets/\n!secrets/keep.txt');
  assert.ok(m.ignores('secrets/keep.txt'));
});

test('leading **/ matches in every directory', () => {
  const m = matcher('**/fixtures');
  assert.ok(m.ignores('fixtures', true));
  assert.ok(m.ignores('a/b/fixtures', true));
});

test('trailing /** matches everything inside', () => {
  const m = matcher('vendor/**');
  assert.ok(m.ignores('vendor/a/b.js'));
  assert.ok(!m.ignores('vendor', true));
});

test('middle /**/ matches zero or more directories', () => {
  const m = matcher('a/**/b');
  assert.ok(m.ignores('a/b'));
  assert.ok(m.ignores('a/x/y/b'));
  assert.ok(!m.ignores('c/a/b'));
});

test('? and character classes match one character', () => {
  const m = matcher('file?.txt\nv[0-9].js\nx[!a].md');
  assert.ok(m.ignores('file1.txt'));
  assert.ok(!m.ignores('file10.txt'));
  assert.ok(m.ignores('v3.js'));
  assert.ok(!m.ignores('vx.js'));
  assert.ok(m.ignores('xb.md'));
  assert.ok(!m.ignores('xa.md'));
});

test('trailing spaces are trimmed unless escaped', () => {
  assert.ok(matcher('notes.txt   ').ignores('notes.txt'));
  assert.ok(matcher('name\\ ').ignores('name '));
});

test('patterns from a nested ignore file apply under its directory only', () => {
  const m = matcher('*.tmp', 'packages/api');
  assert.ok(m.ignores('packages/api/x.tmp'));
  assert.ok(m.ignores('packages/api/src/x.tmp'));
  assert.ok(!m.ignores('packages/web/x.tmp'));
});

test('regex characters in names are literal', () => {
  const m = matcher('a+b(1).txt');
  assert.ok(m.ignores('a+b(1).txt'));
  assert.ok(!m.ignores('aab1.txt'));
});
