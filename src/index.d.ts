export type Severity = 'high' | 'medium' | 'low';
export type Format = 'text' | 'json' | 'sarif';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  target: 'content' | 'path';
  generic: boolean;
  keywords: string[];
  minEntropy: number;
  stopwords: string[];
  pairsWith: string | null;
  validate: 'jwt' | null;
  pattern?: RegExp;
  secretGroups?: number[];
  pathPattern?: RegExp;
  pathExclude?: RegExp | null;
}

export interface RelatedLocation {
  ruleId: string;
  line: number;
  column: number;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  /** POSIX path relative to the scan root. */
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  /** The value with all but a short prefix masked. */
  match: string;
  /** Shannon entropy of the value in bits per character; null for path rules. */
  entropy: number | null;
  /** Rule id plus a hash of the value; stable across edits and moves. */
  fingerprint: string;
  related?: RelatedLocation[];
  /** The unmasked value. Not enumerable, so never serialised. */
  readonly secret: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  filesSkipped: { file: string; reason: string }[];
  suppressed: number;
  rules: Rule[];
}

export interface ScanOptions {
  paths?: string[];
  cwd?: string;
  staged?: boolean;
  rules?: Rule[];
  rulesFile?: string;
  maxSize?: number;
  gitignore?: boolean;
  ignoreFile?: string;
  allowlist?: Allowlist;
}

export interface Writable {
  write(chunk: string): unknown;
}

export class ConfigError extends Error {}

export class IgnoreMatcher {
  add(text: string, base?: string): this;
  ignores(path: string, isDir?: boolean): boolean;
}

export class Allowlist {
  allows(finding: Finding): boolean;
}

export const DEFAULT_RULES_PATH: string;
export const ALLOWLIST_FILE: string;
export const INLINE_ALLOW: string;
export const INLINE_ALLOW_NEXT: string;
export const FORMATS: Format[];
export const VERSION: string;

export function scan(options?: ScanOptions): Promise<ScanResult>;
export function scanContent(text: string, options: { file?: string; rules: Rule[] }): Finding[];
export function scanPath(file: string, rules: Rule[]): Finding[];
export function maskSecret(secret: string): string;
export function fingerprint(ruleId: string, secret: string): string;
export function loadRules(file?: string): Rule[];
export function compileRules(data: unknown, source?: string): Rule[];
export function shannonEntropy(value: string): number;
export function compilePattern(
  line: string,
  base?: string,
): { pattern: string; negate: boolean; dirOnly: boolean; regex: RegExp } | null;
export function parseAllowlist(text: string, source?: string): Allowlist;
export function loadAllowlist(file: string, options?: { required?: boolean }): Allowlist;
export function formatResult(result: ScanResult, format?: Format): string;
export function formatText(result: ScanResult): string;
export function formatJson(result: ScanResult): string;
export function formatSarif(result: ScanResult): string;
export function run(argv: string[], io?: { stdout?: Writable; stderr?: Writable; cwd?: string }): Promise<number>;
