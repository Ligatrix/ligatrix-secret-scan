import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const DEFAULT_RULES_PATH = fileURLToPath(new URL('../rules/default.json', import.meta.url));

const SEVERITIES = new Set(['high', 'medium', 'low']);
const VALIDATORS = new Set(['jwt']);
const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

/** Thrown for a rules file or option that cannot be used. The CLI maps it to exit code 2. */
export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function compile(source, flags, where) {
  try {
    return new RegExp(source, flags);
  } catch (error) {
    throw new ConfigError(`${where}: invalid regular expression: ${error.message}`);
  }
}

/**
 * Validate raw rule definitions and compile their patterns.
 *
 * @param {unknown} data parsed JSON of a rules file
 * @param {string} [source] file name used in error messages
 * @returns {import('./index.d.ts').Rule[]}
 */
export function compileRules(data, source = 'rules') {
  if (!data || typeof data !== 'object' || !Array.isArray(data.rules)) {
    throw new ConfigError(`${source}: expected an object with a "rules" array`);
  }
  const seen = new Set();
  return data.rules.map((raw, index) => {
    const where = `${source}: rule #${index + 1}`;
    if (!raw || typeof raw !== 'object') throw new ConfigError(`${where}: must be an object`);
    const { id } = raw;
    if (typeof id !== 'string' || !ID_PATTERN.test(id)) {
      throw new ConfigError(`${where}: "id" must be lower-case letters, digits and dashes`);
    }
    if (seen.has(id)) throw new ConfigError(`${where}: duplicate id "${id}"`);
    seen.add(id);
    const at = `${source}: rule "${id}"`;
    const severity = raw.severity ?? 'medium';
    if (!SEVERITIES.has(severity)) throw new ConfigError(`${at}: severity must be high, medium or low`);
    const target = raw.target ?? 'content';

    const rule = {
      id,
      name: typeof raw.name === 'string' ? raw.name : id,
      description: typeof raw.description === 'string' ? raw.description : '',
      severity,
      target,
      generic: raw.generic === true,
      keywords: Array.isArray(raw.keywords) ? raw.keywords.map((k) => String(k).toLowerCase()) : [],
      minEntropy: typeof raw.minEntropy === 'number' ? raw.minEntropy : 0,
      stopwords: Array.isArray(raw.stopwords) ? raw.stopwords.map((s) => String(s).toLowerCase()) : [],
      pairsWith: typeof raw.pairsWith === 'string' ? raw.pairsWith : null,
      validate: raw.validate ?? null,
    };

    if (rule.validate !== null && !VALIDATORS.has(rule.validate)) {
      throw new ConfigError(`${at}: unknown validator "${rule.validate}"`);
    }

    if (target === 'path') {
      if (typeof raw.pathPattern !== 'string') throw new ConfigError(`${at}: path rules need "pathPattern"`);
      rule.pathPattern = compile(raw.pathPattern, raw.flags ?? '', at);
      rule.pathExclude = typeof raw.pathExclude === 'string' ? compile(raw.pathExclude, raw.flags ?? '', at) : null;
      return rule;
    }
    if (target !== 'content') throw new ConfigError(`${at}: target must be "content" or "path"`);
    if (typeof raw.pattern !== 'string') throw new ConfigError(`${at}: content rules need "pattern"`);
    const flags = String(raw.flags ?? '').replace(/[gdy]/g, '');
    rule.pattern = compile(raw.pattern, `${flags}gd`, at);
    const groups = raw.secretGroup === undefined ? [1] : [].concat(raw.secretGroup);
    if (!groups.every((g) => Number.isInteger(g) && g >= 0)) {
      throw new ConfigError(`${at}: "secretGroup" must be a group number or a list of them`);
    }
    rule.secretGroups = groups;
    return rule;
  });
}

/**
 * Read and compile a rules file. Defaults to the bundled rules/default.json.
 * @param {string} [file]
 */
export function loadRules(file = DEFAULT_RULES_PATH) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new ConfigError(`cannot read rules file ${file}: ${error.code ?? error.message}`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`${file}: not valid JSON: ${error.message}`);
  }
  return compileRules(data, file);
}
