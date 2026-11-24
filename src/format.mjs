import { readFileSync } from 'node:fs';

export const FORMATS = ['text', 'json', 'sarif'];

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const INFORMATION_URI = 'https://github.com/Ligatrix/ligatrix-secret-scan';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const LEVELS = { high: 'error', medium: 'warning', low: 'note' };
const SECURITY_SEVERITY = { high: '8.9', medium: '6.5', low: '3.0' };

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * Human-readable report: one block per finding with file:line:column, rule, masked value and fingerprint.
 * @param {import('./index.d.ts').ScanResult} result
 */
export function formatText(result) {
  const lines = [];
  for (const f of result.findings) {
    lines.push(`${f.file}:${f.line}:${f.column}  ${f.severity.toUpperCase()}  ${f.ruleName} (${f.ruleId})`);
    lines.push(`    value        ${f.match}`);
    lines.push(`    fingerprint  ${f.fingerprint}`);
    for (const r of f.related ?? []) lines.push(`    pairs with   ${r.ruleId} at line ${r.line}`);
    lines.push('');
  }
  const files = new Set(result.findings.map((f) => f.file)).size;
  const tail = [`scanned ${plural(result.filesScanned, 'file')}`];
  if (result.filesSkipped.length) tail.push(`skipped ${result.filesSkipped.length}`);
  if (result.suppressed) tail.push(`${result.suppressed} allowed by .secretscanignore or inline comments`);
  if (result.findings.length === 0) {
    lines.push(`No secrets found (${tail.join(', ')}).`);
  } else {
    lines.push(`${plural(result.findings.length, 'finding')} in ${plural(files, 'file')} (${tail.join(', ')}).`);
  }
  return `${lines.join('\n')}\n`;
}

/** @param {import('./index.d.ts').ScanResult} result */
export function formatJson(result) {
  const report = {
    tool: 'secret-scan',
    version: VERSION,
    filesScanned: result.filesScanned,
    filesSkipped: result.filesSkipped,
    suppressed: result.suppressed,
    findings: result.findings,
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

function sarifRuleName(id) {
  return id.replace(/(^|-)([a-z0-9])/g, (_, __, ch) => ch.toUpperCase());
}

/**
 * SARIF 2.1.0 log in the shape GitHub code scanning accepts (one run, rules on the driver,
 * results with physical locations and partial fingerprints).
 * @param {import('./index.d.ts').ScanResult} result
 */
export function formatSarif(result) {
  const rules = result.rules;
  const ruleIndex = new Map(rules.map((rule, i) => [rule.id, i]));
  const sarif = {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'secret-scan',
            informationUri: INFORMATION_URI,
            version: VERSION,
            semanticVersion: VERSION,
            rules: rules.map((rule) => ({
              id: rule.id,
              name: sarifRuleName(rule.id),
              shortDescription: { text: rule.name },
              fullDescription: { text: rule.description || rule.name },
              help: {
                text: `${rule.description || rule.name} Remove the value, rotate the credential with its issuer, and load it from the environment or a secrets store.`,
              },
              defaultConfiguration: { level: LEVELS[rule.severity] },
              properties: {
                tags: ['security', 'secrets'],
                precision: rule.generic ? 'medium' : 'high',
                'security-severity': SECURITY_SEVERITY[rule.severity],
              },
            })),
          },
        },
        columnKind: 'utf16CodeUnits',
        results: result.findings.map((f) => {
          const entry = {
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
            level: LEVELS[f.severity],
            message: { text: `${f.ruleName} found: ${f.match}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: encodeURI(f.file), uriBaseId: '%SRCROOT%' },
                  region: {
                    startLine: f.line,
                    startColumn: f.column,
                    endLine: f.endLine,
                    endColumn: Math.max(f.endColumn, f.column + 1),
                  },
                },
              },
            ],
            partialFingerprints: { 'secretFingerprint/v1': f.fingerprint },
          };
          if (f.related?.length) {
            entry.relatedLocations = f.related.map((r, id) => ({
              id,
              message: { text: `Paired ${r.ruleId}` },
              physicalLocation: {
                artifactLocation: { uri: encodeURI(f.file), uriBaseId: '%SRCROOT%' },
                region: { startLine: r.line, startColumn: r.column },
              },
            }));
          }
          return entry;
        }),
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/**
 * @param {import('./index.d.ts').ScanResult} result
 * @param {'text' | 'json' | 'sarif'} format
 */
export function formatResult(result, format = 'text') {
  if (format === 'json') return formatJson(result);
  if (format === 'sarif') return formatSarif(result);
  return formatText(result);
}
