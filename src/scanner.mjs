import { createHash } from 'node:crypto';
import { shannonEntropy, roundEntropy } from './entropy.mjs';

export const INLINE_ALLOW = 'secret-scan:allow';
export const INLINE_ALLOW_NEXT = 'secret-scan:allow-next-line';

/**
 * Mask a secret for display: keep a short recognisable prefix, star the rest.
 * The full value never leaves the scanner in any output format.
 * @param {string} secret
 */
export function maskSecret(secret) {
  const visible = secret.length >= 16 ? 4 : secret.length >= 8 ? 2 : 0;
  return secret.slice(0, visible) + '*'.repeat(Math.min(Math.max(secret.length - visible, 4), 16));
}

/**
 * A stable identifier for a finding: the rule plus a hash of the value. It does not
 * depend on the file or line, so it survives edits and moves, and it never reveals
 * the value itself.
 * @param {string} ruleId
 * @param {string} secret
 */
export function fingerprint(ruleId, secret) {
  return createHash('sha256').update(`${ruleId}\0${secret}`).digest('hex').slice(0, 32);
}

const validators = {
  jwt(secret) {
    const [header] = secret.split('.');
    try {
      const decoded = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
      return decoded !== null && typeof decoded === 'object' && typeof decoded.alg === 'string';
    } catch {
      return false;
    }
  },
};

class LineIndex {
  constructor(text) {
    this.text = text;
    this.starts = [0];
    for (let i = 0; i < text.length; i += 1) {
      if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
    }
  }

  /** 1-based line and column of an offset. */
  position(offset) {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - this.starts[lo] + 1 };
  }

  lineText(line) {
    if (line < 1 || line > this.starts.length) return '';
    const start = this.starts[line - 1];
    const end = line < this.starts.length ? this.starts[line] - 1 : this.text.length;
    return this.text.slice(start, end);
  }
}

function pickSecret(rule, match) {
  for (const group of rule.secretGroups) {
    const value = match[group];
    if (value !== undefined) {
      const [start, end] = match.indices[group];
      return { value, start, end };
    }
  }
  return null;
}

function isInlineAllowed(index, firstLine, lastLine) {
  if (index.lineText(firstLine - 1).includes(INLINE_ALLOW_NEXT)) return true;
  for (let line = firstLine; line <= lastLine; line += 1) {
    if (index.lineText(line).includes(INLINE_ALLOW)) return true;
  }
  return false;
}

function makeFinding(rule, file, secret, start, end, entropy) {
  const finding = {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    file,
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    match: maskSecret(secret),
    entropy: entropy === null ? null : roundEntropy(entropy),
    fingerprint: fingerprint(rule.id, secret),
  };
  // Kept for in-process use (allowlists, tests) but never serialised.
  Object.defineProperty(finding, 'secret', { value: secret, enumerable: false });
  return finding;
}

/**
 * Apply path rules (such as a committed .env file) to a file path.
 * @param {string} file POSIX path relative to the scan root
 * @param {import('./index.d.ts').Rule[]} rules
 */
export function scanPath(file, rules) {
  const findings = [];
  for (const rule of rules) {
    if (rule.target !== 'path') continue;
    if (!rule.pathPattern.test(file)) continue;
    if (rule.pathExclude && rule.pathExclude.test(file)) continue;
    const finding = makeFinding(rule, file, file, { line: 1, column: 1 }, { line: 1, column: 1 }, null);
    finding.match = '(whole file)';
    findings.push(finding);
  }
  return findings;
}

/**
 * Scan text content with the content rules.
 *
 * @param {string} text
 * @param {{ file?: string, rules: import('./index.d.ts').Rule[] }} options
 * @returns {import('./index.d.ts').Finding[]}
 */
export function scanContent(text, { file = '<input>', rules }) {
  const lower = text.toLowerCase();
  const index = new LineIndex(text);
  const raw = [];

  for (const rule of rules) {
    if (rule.target !== 'content') continue;
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lower.includes(k))) continue;
    rule.pattern.lastIndex = 0;
    for (const match of text.matchAll(rule.pattern)) {
      const picked = pickSecret(rule, match);
      if (!picked || picked.value.length === 0) continue;
      const secret = picked.value;
      const lowered = secret.toLowerCase();
      if (rule.stopwords.some((word) => lowered.includes(word))) continue;
      const entropy = shannonEntropy(secret);
      if (entropy < rule.minEntropy) continue;
      if (rule.validate && !validators[rule.validate](secret)) continue;

      const start = index.position(picked.start);
      const end = index.position(picked.end);
      const matchStart = index.position(match.index);
      raw.push({
        finding: makeFinding(rule, file, secret, start, end, entropy),
        rule,
        range: [picked.start, picked.end],
        allowed: isInlineAllowed(index, matchStart.line, start.line),
      });
    }
  }

  // A generic assignment that wraps a value a specific rule already named is a duplicate.
  const specific = raw.filter((r) => !r.rule.generic);
  const kept = raw.filter(
    (r) => !r.rule.generic || !specific.some((s) => s.range[0] < r.range[1] && r.range[0] < s.range[1]),
  );

  // Link paired credentials (an AWS secret key with its access key ID) as related locations.
  for (const entry of kept) {
    if (!entry.rule.pairsWith) continue;
    const partners = kept.filter((other) => other.rule.id === entry.rule.pairsWith);
    if (partners.length === 0) continue;
    const nearest = partners.reduce((best, other) =>
      Math.abs(other.range[0] - entry.range[0]) < Math.abs(best.range[0] - entry.range[0]) ? other : best,
    );
    entry.finding.related = [
      { ruleId: nearest.rule.id, line: nearest.finding.line, column: nearest.finding.column },
    ];
  }

  return kept
    .filter((entry) => !entry.allowed)
    .map((entry) => entry.finding)
    .sort((a, b) => a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId));
}
