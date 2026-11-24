#!/usr/bin/env node
// Style check for tracked source files: no trailing whitespace, no tabs, a final newline.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const CHECKED = /\.(?:mjs|js|cjs|ts|json|md|yml|yaml)$|(?:^|\/)(?:pre-commit|\.editorconfig|\.gitignore|CODEOWNERS)$/;

function trackedFiles() {
  try {
    return execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
  } catch {
    console.error('lint: run from inside the git repository');
    process.exit(2);
  }
}

const problems = [];
for (const file of trackedFiles().filter((f) => CHECKED.test(f))) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    continue; // deleted in the working tree
  }
  if (text.length > 0 && !text.endsWith('\n')) problems.push(`${file}: missing final newline`);
  text.split('\n').forEach((line, i) => {
    if (/[ \t]+$/.test(line)) problems.push(`${file}:${i + 1}: trailing whitespace`);
    if (line.includes('\t')) problems.push(`${file}:${i + 1}: tab character`);
  });
}

if (problems.length > 0) {
  console.error(problems.join('\n'));
  console.error(`\nlint: ${problems.length} problem${problems.length === 1 ? '' : 's'}`);
  process.exit(1);
}
console.log('lint: ok');
