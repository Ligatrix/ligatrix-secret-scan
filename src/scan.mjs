import { join, resolve } from 'node:path';
import { ALLOWLIST_FILE, Allowlist, loadAllowlist } from './allowlist.mjs';
import { readStaged, repoTop, stagedPaths, stagedSize } from './git.mjs';
import { ConfigError, loadRules } from './rules.mjs';
import { scanContent, scanPath } from './scanner.mjs';
import { DEFAULT_MAX_SIZE, collectFiles, hasBinaryExtension, looksBinary, readCandidate } from './walk.mjs';

function scanOne(file, text, rules) {
  return [...scanPath(file, rules), ...scanContent(text, { file, rules })];
}

/**
 * Scan files on disk, or the staged changes of a git repository.
 *
 * @param {import('./index.d.ts').ScanOptions} [options]
 * @returns {Promise<import('./index.d.ts').ScanResult>}
 */
export async function scan(options = {}) {
  const cwd = resolve(options.cwd ?? process.cwd());
  const rules = options.rules ?? loadRules(options.rulesFile);
  const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
  const staged = options.staged === true;
  const root = staged ? repoTop(cwd) : cwd;

  let allowlist;
  if (options.allowlist instanceof Allowlist) allowlist = options.allowlist;
  else if (options.ignoreFile) allowlist = loadAllowlist(resolve(cwd, options.ignoreFile), { required: true });
  else allowlist = loadAllowlist(join(root, ALLOWLIST_FILE));

  const all = [];
  const skipped = [];
  let scanned = 0;

  if (staged) {
    for (const path of stagedPaths(root)) {
      if (hasBinaryExtension(path)) {
        skipped.push({ file: path, reason: 'binary' });
        continue;
      }
      if (stagedSize(root, path) > maxSize) {
        skipped.push({ file: path, reason: 'too large' });
        continue;
      }
      const buffer = readStaged(root, path);
      if (looksBinary(buffer)) {
        skipped.push({ file: path, reason: 'binary' });
        continue;
      }
      scanned += 1;
      all.push(...scanOne(path, buffer.toString('utf8'), rules));
    }
  } else {
    let collected;
    try {
      collected = await collectFiles(options.paths?.length ? options.paths : ['.'], {
        root,
        gitignore: options.gitignore !== false,
      });
    } catch (error) {
      if (error.code === 'ENOENT') throw new ConfigError(error.message);
      throw error;
    }
    skipped.push(...collected.skipped);
    for (const file of collected.files) {
      const { text, reason } = await readCandidate(file.abs, file.size, maxSize);
      if (reason) {
        skipped.push({ file: file.rel, reason });
        continue;
      }
      scanned += 1;
      all.push(...scanOne(file.rel, text, rules));
    }
  }

  const findings = all.filter((finding) => !allowlist.allows(finding));
  return {
    findings,
    filesScanned: scanned,
    filesSkipped: skipped,
    suppressed: all.length - findings.length,
    rules,
  };
}
