import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { FORMATS, VERSION, formatResult } from './format.mjs';
import { ConfigError, loadRules } from './rules.mjs';
import { scan } from './scan.mjs';
import { DEFAULT_MAX_SIZE } from './walk.mjs';

export const EXIT_CLEAN = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;

export const HELP = `Usage: secret-scan [options] [path ...]

Scan files for credentials before they are committed. Paths default to the
current directory; directories are walked with .gitignore applied.

Options:
  --staged              scan the files staged for commit (git diff --cached)
  -f, --format <name>   output format: text (default), json or sarif
  -o, --output <file>   write the report to a file instead of stdout
  --rules <file>        use this rules file instead of the bundled rules
  --ignore-file <file>  allowlist to use (default: .secretscanignore at the root)
  --max-size <size>     skip files larger than this (default 1m; accepts k and m)
  --no-gitignore        walk every file, including those .gitignore excludes
  --list-rules          print the rules and exit
  -h, --help            print this help and exit
  -v, --version         print the version and exit

Exit codes: 0 no findings, 1 findings, 2 usage or configuration error.
`;

class UsageError extends Error {}

/** Parse a size such as 500000, 512k or 2m into bytes. */
export function parseSize(value) {
  const match = /^(\d+(?:\.\d+)?)\s*([km]?)b?$/i.exec(String(value).trim());
  if (!match) throw new UsageError(`invalid size "${value}" (examples: 500000, 512k, 2m)`);
  const unit = { '': 1, k: 1024, m: 1024 * 1024 }[match[2].toLowerCase()];
  return Math.floor(Number(match[1]) * unit);
}

/**
 * Parse command-line arguments.
 * @param {string[]} argv arguments after the program name
 */
export function parseArgs(argv) {
  const options = {
    paths: [],
    format: 'text',
    staged: false,
    gitignore: true,
    maxSize: DEFAULT_MAX_SIZE,
    output: null,
    rulesFile: undefined,
    ignoreFile: undefined,
    help: false,
    version: false,
    listRules: false,
  };
  const valueFlags = new Set(['--format', '-f', '--output', '-o', '--rules', '--ignore-file', '--max-size']);

  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];
    let value;
    if (arg === '--') {
      options.paths.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--') && arg.includes('=')) {
      value = arg.slice(arg.indexOf('=') + 1);
      arg = arg.slice(0, arg.indexOf('='));
    }
    if (valueFlags.has(arg) && value === undefined) {
      if (i + 1 >= argv.length) throw new UsageError(`${arg} needs a value`);
      i += 1;
      value = argv[i];
    }
    switch (arg) {
      case '--staged': options.staged = true; break;
      case '--no-gitignore': options.gitignore = false; break;
      case '--list-rules': options.listRules = true; break;
      case '-h': case '--help': options.help = true; break;
      case '-v': case '--version': options.version = true; break;
      case '-f': case '--format':
        if (!FORMATS.includes(value)) throw new UsageError(`unknown format "${value}" (use ${FORMATS.join(', ')})`);
        options.format = value;
        break;
      case '-o': case '--output': options.output = value; break;
      case '--rules': options.rulesFile = value; break;
      case '--ignore-file': options.ignoreFile = value; break;
      case '--max-size': options.maxSize = parseSize(value); break;
      default:
        if (arg.startsWith('-') && arg !== '-') throw new UsageError(`unknown option "${arg}"`);
        options.paths.push(arg);
    }
  }
  if (options.staged && options.paths.length > 0) {
    throw new UsageError('--staged scans the index; do not pass paths with it');
  }
  return options;
}

function listRules(rules) {
  const width = Math.max(...rules.map((r) => r.id.length));
  return `${rules.map((r) => `${r.id.padEnd(width)}  ${r.severity.padEnd(6)}  ${r.name}`).join('\n')}\n`;
}

/**
 * Run the command line. Returns the exit code instead of exiting, so it can be tested in-process.
 *
 * @param {string[]} argv
 * @param {{ stdout?: { write(s: string): unknown }, stderr?: { write(s: string): unknown }, cwd?: string }} [io]
 * @returns {Promise<number>}
 */
export async function run(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();
  try {
    const options = parseArgs(argv);
    if (options.help) {
      stdout.write(HELP);
      return EXIT_CLEAN;
    }
    if (options.version) {
      stdout.write(`${VERSION}\n`);
      return EXIT_CLEAN;
    }
    const rules = loadRules(options.rulesFile ? resolve(cwd, options.rulesFile) : undefined);
    if (options.listRules) {
      stdout.write(listRules(rules));
      return EXIT_CLEAN;
    }
    const result = await scan({ ...options, rules, cwd });
    const report = formatResult(result, options.format);
    if (options.output) {
      writeFileSync(resolve(cwd, options.output), report);
      if (options.format !== 'text') stderr.write(formatResult(result, 'text').split('\n').filter(Boolean).pop() + '\n');
    } else {
      stdout.write(report);
    }
    return result.findings.length > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
  } catch (error) {
    if (error instanceof UsageError || error instanceof ConfigError) {
      stderr.write(`secret-scan: ${error.message}\n`);
      if (error instanceof UsageError) stderr.write('Run "secret-scan --help" for usage.\n');
      return EXIT_USAGE;
    }
    stderr.write(`secret-scan: ${error.stack ?? error}\n`);
    return EXIT_USAGE;
  }
}
