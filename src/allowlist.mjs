import { readFileSync } from 'node:fs';
import { IgnoreMatcher } from './gitignore.mjs';
import { ConfigError } from './rules.mjs';

export const ALLOWLIST_FILE = '.secretscanignore';

const FINGERPRINT = /^[0-9a-f]{32}$/;

/**
 * Parse a .secretscanignore file.
 *
 * Each line is one of:
 *   - a comment (`# ...`) or blank;
 *   - `fingerprint:<32 hex>` to accept one known value wherever it appears;
 *   - `rule:<rule id>` to turn a rule off, or `rule:<rule id> <glob>` to turn it off for matching paths;
 *   - a path or glob in .gitignore syntax (negation with `!` works) to accept every finding in matching files.
 *
 * @param {string} text
 * @param {string} [source] name used in error messages
 */
export function parseAllowlist(text, source = ALLOWLIST_FILE) {
  const fingerprints = new Set();
  const paths = new IgnoreMatcher();
  const ruleOff = [];
  text.split('\n').forEach((rawLine, index) => {
    const line = rawLine.replace(/\r$/, '').trim();
    if (line === '' || line.startsWith('#')) return;
    if (line.startsWith('fingerprint:')) {
      const value = line.slice('fingerprint:'.length).trim().toLowerCase();
      if (!FINGERPRINT.test(value)) {
        throw new ConfigError(`${source}:${index + 1}: a fingerprint is 32 hexadecimal characters`);
      }
      fingerprints.add(value);
      return;
    }
    if (line.startsWith('rule:')) {
      const [id, glob] = line.slice('rule:'.length).trim().split(/\s+/, 2);
      if (!id) throw new ConfigError(`${source}:${index + 1}: "rule:" needs a rule id`);
      ruleOff.push({ id, paths: glob ? new IgnoreMatcher().add(glob) : null });
      return;
    }
    paths.add(line);
  });
  return new Allowlist(fingerprints, paths, ruleOff);
}

export class Allowlist {
  constructor(fingerprints = new Set(), paths = new IgnoreMatcher(), ruleOff = []) {
    this.fingerprints = fingerprints;
    this.paths = paths;
    this.ruleOff = ruleOff;
  }

  /** @param {import('./index.d.ts').Finding} finding */
  allows(finding) {
    if (this.fingerprints.has(finding.fingerprint)) return true;
    if (this.paths.ignores(finding.file, false)) return true;
    return this.ruleOff.some(
      (entry) => entry.id === finding.ruleId && (entry.paths === null || entry.paths.ignores(finding.file, false)),
    );
  }
}

/**
 * Read an allowlist file. A missing file is an empty allowlist unless `required` is set.
 * @param {string} file
 * @param {{ required?: boolean }} [options]
 */
export function loadAllowlist(file, { required = false } = {}) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    if (!required && error.code === 'ENOENT') return new Allowlist();
    throw new ConfigError(`cannot read allowlist ${file}: ${error.code ?? error.message}`);
  }
  return parseAllowlist(text, file);
}
