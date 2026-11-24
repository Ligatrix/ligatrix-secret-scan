import { existsSync, readFileSync } from 'node:fs';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { IgnoreMatcher } from './gitignore.mjs';

export const DEFAULT_MAX_SIZE = 1024 * 1024;

const BINARY_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'webp', 'avif', 'tiff', 'psd',
  'pdf', 'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'jar', 'war',
  'exe', 'dll', 'so', 'dylib', 'o', 'a', 'class', 'wasm', 'bin',
  'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp3', 'mp4', 'mov', 'avi', 'wav', 'ogg', 'webm',
  'sqlite', 'db', 'pyc',
]);

/** POSIX form of a relative path. */
export function toPosix(path) {
  return path.split(sep).join('/');
}

/** True when the name's extension marks a binary format. */
export function hasBinaryExtension(name) {
  const dot = name.lastIndexOf('.');
  return dot > 0 && BINARY_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}

/** True when the first 8000 bytes hold a NUL byte, the same test git uses. */
export function looksBinary(buffer) {
  return buffer.subarray(0, 8000).includes(0);
}

/** Nearest directory at or above `dir` holding a .git entry, or null. */
export function findRepoTop(dir) {
  let current = resolve(dir);
  for (;;) {
    if (existsSync(join(current, '.git'))) return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function readIfExists(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Matcher primed with .git/info/exclude and every .gitignore from the repository top down to `dir`. */
function matcherFor(dir) {
  const top = findRepoTop(dir) ?? dir;
  const matcher = new IgnoreMatcher();
  const exclude = readIfExists(join(top, '.git', 'info', 'exclude'));
  if (exclude) matcher.add(exclude, '');
  const chain = [];
  for (let current = dir; ; current = dirname(current)) {
    chain.unshift(current);
    if (current === top || dirname(current) === current) break;
  }
  for (const folder of chain) {
    const text = readIfExists(join(folder, '.gitignore'));
    if (text) matcher.add(text, toPosix(relative(top, folder)));
  }
  return { top, matcher };
}

/**
 * Read one candidate file and decide whether to scan it.
 * @returns {Promise<{ text?: string, reason?: string }>}
 */
export async function readCandidate(abs, size, maxSize) {
  if (hasBinaryExtension(abs)) return { reason: 'binary' };
  if (size > maxSize) return { reason: 'too large' };
  const buffer = await readFile(abs);
  if (looksBinary(buffer)) return { reason: 'binary' };
  return { text: buffer.toString('utf8') };
}

/**
 * Collect the files under the given targets.
 *
 * @param {string[]} targets files or directories
 * @param {{ root: string, gitignore?: boolean }} options
 * @returns {Promise<{ files: { abs: string, rel: string, size: number }[], skipped: { file: string, reason: string }[] }>}
 */
export async function collectFiles(targets, { root, gitignore = true }) {
  const files = [];
  const skipped = [];
  const seen = new Set();

  const add = (abs, size) => {
    if (seen.has(abs)) return;
    seen.add(abs);
    files.push({ abs, rel: toPosix(relative(root, abs)) || abs, size });
  };

  // The starting directory's own .gitignore is already in the matcher (see matcherFor).
  async function walk(dir, top, matcher, loadOwnIgnore = false) {
    if (gitignore && loadOwnIgnore) {
      const text = readIfExists(join(dir, '.gitignore'));
      if (text) matcher.add(text, toPosix(relative(top, dir)));
    }
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      const isDir = entry.isDirectory();
      if (isDir && entry.name === '.git') continue;
      if (gitignore && matcher.ignores(toPosix(relative(top, abs)), isDir)) continue;
      if (isDir) await walk(abs, top, matcher, true);
      else if (entry.isFile()) add(abs, (await lstat(abs)).size);
    }
  }

  for (const target of targets) {
    const abs = resolve(root, target);
    let info;
    try {
      info = await lstat(abs);
    } catch {
      const error = new Error(`no such file or directory: ${target}`);
      error.code = 'ENOENT';
      throw error;
    }
    if (info.isDirectory()) {
      if (gitignore) {
        const { top, matcher } = matcherFor(abs);
        await walk(abs, top, matcher);
      } else {
        await walk(abs, abs, new IgnoreMatcher());
      }
    } else if (info.isFile()) {
      add(abs, info.size);
    } else {
      skipped.push({ file: toPosix(relative(root, abs)), reason: 'not a regular file' });
    }
  }
  return { files, skipped };
}
