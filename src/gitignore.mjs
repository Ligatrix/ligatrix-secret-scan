/**
 * A gitignore matcher covering the parts of the format real repositories use:
 * comments, escaped characters, trailing-space trimming, negation, directory-only
 * patterns, anchoring by slash, `*`, `?`, character classes and `**` in leading,
 * trailing and middle positions. Patterns from nested .gitignore files apply
 * relative to their own directory, and a later match overrides an earlier one.
 */

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function globSegment(segment) {
  let out = '';
  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    if (ch === '\\' && i + 1 < segment.length) {
      out += escapeRegExp(segment[i + 1]);
      i += 1;
    } else if (ch === '*') {
      while (segment[i + 1] === '*') i += 1;
      out += '[^/]*';
    } else if (ch === '?') {
      out += '[^/]';
    } else if (ch === '[') {
      const close = segment.indexOf(']', i + 2);
      if (close === -1) {
        out += '\\[';
        continue;
      }
      let body = segment.slice(i + 1, close);
      let negate = false;
      if (body[0] === '!' || body[0] === '^') {
        negate = true;
        body = body.slice(1);
      }
      body = body.replace(/\\/g, '\\\\').replace(/\]/g, '\\]');
      out += negate ? `[^/${body}]` : `[${body}]`;
      i = close;
    } else {
      out += escapeRegExp(ch);
    }
  }
  return out;
}

function globToSource(glob) {
  const segments = glob.split('/');
  let out = '';
  segments.forEach((segment, i) => {
    const last = i === segments.length - 1;
    if (segment === '**') {
      if (segments.length === 1) out += '.*';
      else if (last) out += '.+';
      else out += '(?:.*/)?';
      return;
    }
    out += globSegment(segment);
    if (!last) out += '/';
  });
  return out;
}

/**
 * Compile one line of a gitignore file. Returns null for blanks and comments.
 * @param {string} line
 * @param {string} [base] directory of the ignore file, relative to the matcher root
 */
export function compilePattern(line, base = '') {
  let text = line.replace(/\r$/, '');
  if (text === '' || text.startsWith('#')) return null;
  // Trailing spaces are ignored unless escaped with a backslash.
  text = text.replace(/(?<!\\)[ \t]+$/, '');
  if (text === '') return null;
  let negate = false;
  if (text.startsWith('!')) {
    negate = true;
    text = text.slice(1);
  } else if (text.startsWith('\\!') || text.startsWith('\\#')) {
    text = text.slice(1);
  }
  let dirOnly = false;
  if (text.endsWith('/') && !text.endsWith('\\/')) {
    dirOnly = true;
    text = text.replace(/\/+$/, '');
  }
  if (text === '') return null;
  const anchored = text.includes('/');
  if (text.startsWith('/')) text = text.slice(1);
  const prefix = base ? `${escapeRegExp(base.replace(/\/+$/, ''))}/` : '';
  const body = globToSource(text);
  const source = anchored ? `^${prefix}${body}$` : `^${prefix}(?:.*/)?${body}$`;
  return { pattern: line, negate, dirOnly, regex: new RegExp(source) };
}

export class IgnoreMatcher {
  constructor() {
    this.rules = [];
  }

  /**
   * Add the patterns of one ignore file.
   * @param {string} text file contents
   * @param {string} [base] the file's directory relative to the matcher root ('' for the root)
   */
  add(text, base = '') {
    for (const line of text.split('\n')) {
      const rule = compilePattern(line, base);
      if (rule) this.rules.push(rule);
    }
    return this;
  }

  /** Result of the patterns for this exact path, ignoring its parents. */
  matchesSelf(path, isDir) {
    let ignored = false;
    for (const rule of this.rules) {
      if (rule.dirOnly && !isDir) continue;
      if (rule.regex.test(path)) ignored = !rule.negate;
    }
    return ignored;
  }

  /**
   * Whether a path is ignored. A file inside an ignored directory stays ignored,
   * as in git, even when a later pattern would re-include it.
   * @param {string} path POSIX path relative to the matcher root
   * @param {boolean} [isDir]
   */
  ignores(path, isDir = false) {
    const parts = path.split('/').filter(Boolean);
    for (let i = 1; i < parts.length; i += 1) {
      if (this.matchesSelf(parts.slice(0, i).join('/'), true)) return true;
    }
    return this.matchesSelf(parts.join('/'), isDir);
  }
}
