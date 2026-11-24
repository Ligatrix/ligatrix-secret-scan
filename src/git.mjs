import { execFileSync } from 'node:child_process';
import { ConfigError } from './rules.mjs';

const MAX_BUFFER = 64 * 1024 * 1024;

function git(args, cwd, encoding = 'utf8') {
  return execFileSync('git', args, { cwd, encoding, maxBuffer: MAX_BUFFER, stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Top-level directory of the repository containing `cwd`. */
export function repoTop(cwd) {
  try {
    return git(['rev-parse', '--show-toplevel'], cwd).trim();
  } catch {
    throw new ConfigError('--staged needs to run inside a git repository');
  }
}

/**
 * Paths of files added, copied, modified or renamed in the index, relative to the repository top.
 * Deleted files are left out: they cannot add a secret.
 * @param {string} top
 */
export function stagedPaths(top) {
  const out = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], top);
  return out.split('\0').filter(Boolean);
}

/** Size in bytes of a staged file's blob. */
export function stagedSize(top, path) {
  return Number(git(['cat-file', '-s', `:${path}`], top).trim());
}

/**
 * The staged content of a file: what will be committed, not what is in the working tree.
 * @returns {Buffer}
 */
export function readStaged(top, path) {
  return git(['show', `:${path}`], top, 'buffer');
}
