// Test values are assembled at run time from a seeded random source. No file in this
// repository holds a literal credential, so the repository scans clean and no
// hosting provider's push protection is tripped by the fixtures.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const DIGITS = '0123456789';
export const ALNUM = UPPER + LOWER + DIGITS;
export const HEX = '0123456789abcdef';
export const BASE32 = `${UPPER}234567`;
export const BASE64 = `${ALNUM}+/`;
export const BASE64URL = `${ALNUM}-_`;

/** Deterministic pseudo-random string (mulberry32), so failures reproduce. */
export function rand(length, seed = 1, alphabet = ALNUM) {
  let state = seed >>> 0;
  let out = '';
  for (let i = 0; i < length; i += 1) {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    const r = ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    out += alphabet[Math.floor(r * alphabet.length)];
  }
  return out;
}

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Builders for one realistic-looking value per rule. */
export const fake = {
  pemBody: (seed = 1) => rand(64, seed, BASE64),
  privateKey: (kind = 'RSA ', seed = 1) =>
    [`-----BEGIN ${kind}PRIVATE KEY-----`, rand(64, seed, BASE64), rand(64, seed + 1, BASE64), `-----END ${kind}PRIVATE KEY-----`].join('\n'),
  pgpKey: (seed = 1) =>
    ['-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Version: Demo 1.0', '', rand(64, seed, BASE64), '-----END PGP PRIVATE KEY BLOCK-----'].join('\n'),
  awsKeyId: (seed = 2) => `AK${'IA'}${rand(16, seed, BASE32)}`,
  awsSecret: (seed = 3) => rand(40, seed, BASE64),
  github: (prefix = 'ghp', seed = 4) => `${prefix}_${rand(36, seed)}`,
  githubFine: (seed = 5) => `github${'_pat_'}${rand(22, seed)}_${rand(59, seed + 1)}`,
  stripe: (kind = 'sk', mode = 'live', seed = 6) => `${kind}_${mode}_${rand(32, seed)}`,
  slackBot: (seed = 7) => `xox${'b'}-${rand(12, seed, DIGITS)}-${rand(13, seed + 1, DIGITS)}-${rand(24, seed + 2)}`,
  slackWebhook: (seed = 8) =>
    `https://hooks.slack.com/services/T${rand(10, seed, UPPER + DIGITS)}/B${rand(10, seed + 1, UPPER + DIGITS)}/${rand(24, seed + 2)}`,
  google: (seed = 9) => `A${'Iza'}${rand(35, seed, `${ALNUM}_-`)}`,
  twilioKey: (seed = 10) => `S${'K'}${rand(32, seed, HEX)}`,
  twilioToken: (seed = 11) => rand(32, seed, HEX),
  sendgrid: (seed = 12) => `S${'G.'}${rand(22, seed, BASE64URL)}.${rand(43, seed + 1, BASE64URL)}`,
  jwt: (seed = 13) =>
    `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: rand(12, seed), iat: 1764000000 })}.${rand(43, seed + 1, BASE64URL)}`,
  password: (seed = 14) => rand(20, seed, `${ALNUM}!%&*+-.=?@^_~`),
};

/** Create a temporary directory populated with the given files. */
export function tempTree(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'secret-scan-test-'));
  for (const [name, content] of Object.entries(files)) {
    const path = join(dir, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Collect writes to a fake stream. */
export function sink() {
  const chunks = [];
  return { write: (s) => chunks.push(s), get text() { return chunks.join(''); } };
}
