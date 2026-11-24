# ligatrix-secret-scan

A zero-dependency command-line scanner that stops credentials from being committed to a repository.

![CI](https://github.com/Ligatrix/ligatrix-secret-scan/actions/workflows/ci.yml/badge.svg)

## Why

A cloud key or payment key that reaches a git remote has to be treated as public: it lives in every clone and in the
history, and removing it means rotating the credential, auditing what it touched and rewriting history. The cheapest
place to stop it is the developer's own machine, before the commit exists, with the same check repeated in CI for
anything that slips past. `secret-scan` does both with one binary, no install step and no network access, and it is
tuned so that a team keeps it switched on: placeholders, environment lookups and documented samples do not fail a
build.

## Quick start

```sh
git clone https://github.com/Ligatrix/ligatrix-secret-scan.git && cd ligatrix-secret-scan
node bin/secret-scan.mjs .
node examples/demo.mjs
```

The second command scans this repository (it is clean, exit code 0). The third builds a throwaway project for
Corvane Supply Co., a fictional distributor used in this demo, with planted credentials, and scans it.

Requires Node.js 20 or later. To use it in another project, add it as a development dependency straight from GitHub
(`npm install --save-dev github:Ligatrix/ligatrix-secret-scan`) and call `secret-scan`, or vendor the folder and run
`node path/to/bin/secret-scan.mjs`.

## Usage

```text
secret-scan [options] [path ...]

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
```

| Exit code | Meaning |
| --- | --- |
| `0` | No findings |
| `1` | One or more findings |
| `2` | Usage or configuration error (unknown option, missing path, invalid rules or allowlist, `--staged` outside a repository) |

Paths default to the current directory. Directories are walked with `.gitignore` applied (nested files, negation,
`**`, and `.git/info/exclude`); `.git` and symbolic links are never followed; binary files and files over the size
limit are skipped and counted. A file named explicitly on the command line is scanned even if it is ignored.

`--staged` reads the list from `git diff --cached` and scans the **staged blob** of each file, not the working copy,
so what is checked is exactly what will be committed. Paths are reported from the repository top.

### Text output (default)

`node examples/demo.mjs` prints:

```text
.env:1:1  MEDIUM  Committed .env file (dotenv-file)
    value        (whole file)
    fingerprint  b706a7117ce22f4b45fab6a7d247a3ad

config/database.yml:1:24  HIGH  Database URL with password (database-url)
    value        hfma****************
    fingerprint  3ca980d166081270c294e21e5c47c29c

deploy/credentials:2:21  HIGH  AWS access key ID (aws-access-key-id)
    value        AKIA****************
    fingerprint  f27b645c86c27e8483db17ca2d51acbc

deploy/credentials:3:25  HIGH  AWS secret access key (aws-secret-access-key)
    value        uCdE****************
    fingerprint  a9a4fefeba59cdfc73cd73d88f730ffe
    pairs with   aws-access-key-id at line 2

src/orders.js:3:28  HIGH  Stripe live secret key (stripe-live-key)
    value        sk_l****************
    fingerprint  73e4cb3bda08691b95a6219507a81d2f

5 findings in 4 files (scanned 7 files).
```

The demo's `docs/setup.md` also holds a key, marked `secret-scan:allow`, so it is not reported. Values are always
masked; no output format ever contains a full credential.

### JSON output

`node examples/demo.mjs --format json` (one finding shown):

```json
{
  "tool": "secret-scan",
  "version": "1.0.0",
  "filesScanned": 7,
  "filesSkipped": [],
  "suppressed": 0,
  "findings": [
    {
      "ruleId": "aws-secret-access-key",
      "ruleName": "AWS secret access key",
      "severity": "high",
      "file": "deploy/credentials",
      "line": 3,
      "column": 25,
      "endLine": 3,
      "endColumn": 65,
      "match": "uCdE****************",
      "entropy": 4.83,
      "fingerprint": "a9a4fefeba59cdfc73cd73d88f730ffe",
      "related": [{ "ruleId": "aws-access-key-id", "line": 2, "column": 21 }]
    }
  ]
}
```

### SARIF output

`node examples/demo.mjs --format sarif` writes a SARIF 2.1.0 log: one run, every rule on the driver with a
`security-severity`, and results with a physical location and a `partialFingerprints` entry, the shape GitHub code
scanning accepts. One result:

```json
{
  "ruleId": "stripe-live-key",
  "ruleIndex": 5,
  "level": "error",
  "message": { "text": "Stripe live secret key found: sk_l****************" },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "src/orders.js", "uriBaseId": "%SRCROOT%" },
        "region": { "startLine": 3, "startColumn": 28, "endLine": 3, "endColumn": 68 }
      }
    }
  ],
  "partialFingerprints": { "secretFingerprint/v1": "73e4cb3bda08691b95a6219507a81d2f" }
}
```

## Rules

The rules live in [`rules/default.json`](rules/default.json); `node bin/secret-scan.mjs --list-rules` prints them.

| Rule | Severity | Finds | False-positive guard |
| --- | --- | --- | --- |
| `private-key` | high | PEM and OpenPGP private key blocks: RSA, EC, DSA, OpenSSH, PKCS#8, encrypted, PGP | Needs key material after the header, entropy ≥ 3.5 |
| `aws-access-key-id` | high | `AKIA`/`ASIA`/`ABIA`/`ACCA` access key IDs | Entropy ≥ 3.0; AWS documentation examples skipped |
| `aws-secret-access-key` | high | 40-character secret keys next to an AWS key name; linked to the access key ID in the same file | Needs the name beside it, entropy ≥ 4.0 |
| `github-token` | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens | Exact length and word boundaries, entropy ≥ 3.0 |
| `github-fine-grained-token` | high | `github_pat_` tokens | Exact shape |
| `stripe-live-key` | high | `sk_live_` secret keys | Test-mode keys ignored |
| `stripe-restricted-key` | high | `rk_live_` restricted keys | Test-mode keys ignored |
| `slack-token` | high | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` and `xapp-` tokens | Numeric workspace segment required |
| `slack-webhook` | medium | `hooks.slack.com` webhook and workflow URLs | Needs team, channel and secret parts |
| `google-api-key` | medium | `AIza` API keys | Exact length |
| `twilio-api-key` | medium | `SK` API key SIDs | Lower-case hex body, entropy ≥ 3.0 |
| `twilio-auth-token` | high | 32-hex auth tokens next to a Twilio name | Needs the name beside it |
| `sendgrid-api-key` | high | `SG.` API keys | Exact shape, entropy ≥ 3.5 |
| `jwt` | medium | Signed JSON Web Tokens | Header must decode to JSON with an `alg` field |
| `database-url` | high | Postgres, MySQL, MariaDB, SQL Server, MongoDB, Redis and AMQP URLs with a password | Placeholder passwords (`password`, `changeme`, `${...}`) skipped |
| `generic-assignment` | medium | `password=`, `secret:`, `token =`, `apiKey:` and similar with a quoted value, or an unquoted value on a `KEY=value` line | Entropy ≥ 3.0; `process.env`, `os.environ`, templates, escaped strings and placeholder words skipped; dropped when a specific rule already reports the same value |
| `dotenv-file` | medium | A committed `.env` or `.env.<name>` file | `.env.example`, `.sample`, `.template`, `.dist`, `.defaults`, `.schema` allowed |

A rule is a JSON object: `id`, `name`, `description`, `severity`, a `pattern` (JavaScript regular expression) with
the value in `secretGroup` (a group number or a list of them, the first that matched wins), and optional `flags`,
`keywords` (a cheap pre-check), `minEntropy`, `stopwords`, `pairsWith` and `validate`. Path rules use `target: "path"`
with `pathPattern` and `pathExclude`. Pass your own file with `--rules`.

## Accepting a finding

Three ways, from narrowest to widest:

- **Inline:** put `secret-scan:allow` in a comment on the line, or `secret-scan:allow-next-line` on the line above.
  On a private key, the comment goes on the `BEGIN` line.
- **By fingerprint:** add `fingerprint:<value>` to `.secretscanignore`. The fingerprint is a hash of the rule and the
  value, so it follows the value when lines move and never reveals it.
- **By path or rule:** `.secretscanignore` takes `.gitignore`-style globs (`test/fixtures/**`, with `!` to
  re-include) and `rule:<id>` or `rule:<id> <glob>` to switch a rule off everywhere or under a path.

```text
# .secretscanignore
fingerprint:b706a7117ce22f4b45fab6a7d247a3ad
test/fixtures/**
rule:jwt docs/**
```

## Pre-commit hook

[`hooks/pre-commit`](hooks/pre-commit) runs `secret-scan --staged` and blocks the commit on a finding:

```sh
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Or, to share it through the repository, copy it into a tracked folder such as `.githooks/` and run
`git config core.hooksPath .githooks` once per clone.

## Using it in CI

The hook can be bypassed with `git commit --no-verify`, so run the same scan on every push. With GitHub Actions,
upload SARIF so findings appear in the Security tab and on the pull request:

```yaml
name: Secret scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install --save-dev github:Ligatrix/ligatrix-secret-scan
      - run: npx secret-scan --format sarif --output secret-scan.sarif .
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secret-scan.sarif
```

The scan step fails the job on a finding (exit code 1); `if: always()` still uploads the report. On any other CI
system, `npx secret-scan .` is enough: the exit code fails the build and the text report shows file, line and the
masked value. `--format json` is there for dashboards and custom gates.

## Library use

```js
import { scan, formatResult } from '@ligatrix/secret-scan';

const result = await scan({ paths: ['src'], cwd: process.cwd() });
console.log(formatResult(result, 'text'));
```

Types are in [`src/index.d.ts`](src/index.d.ts).

## Design notes

- **No dependencies.** A tool that guards credentials should not pull a dependency tree into the commit path. It is
  plain Node.js ESM, so it runs wherever `node` does, with no install step and no network.
- **Specific rules first, entropy second.** Known token formats are matched by exact shape; entropy is a second gate
  that drops shaped matches like `ghp_xxxx…`. The generic `password=` rule leans on entropy, stopwords and
  context, and it yields to a specific rule on the same value so each credential is reported once.
- **Fingerprints ignore position.** A fingerprint is the rule plus a hash of the value, so an accepted value stays
  accepted when code moves, and the allowlist never holds the value itself.
- **Staged mode reads the index.** Scanning the working copy would miss a value that was staged and then edited
  away, and flag one that was never staged.
- **Our own `.gitignore` matcher.** Shelling out to `git check-ignore` would tie directory scans to a git checkout;
  the matcher covers the pattern features real repositories use, and is tested against them.
- **Regex scanning is line-agnostic.** Rules run over the whole file, so multi-line values such as private key
  blocks are matched, and positions are reported as 1-based UTF-16 columns, as SARIF expects.

## Testing

```sh
npm test
```

The suite (`node:test`, no dependencies) covers every rule with a true positive and a near miss, entropy, the
allowlist and inline comments, the `.gitignore` matcher, the walk (binary, size, symbolic links), the three output
formats, exit codes, `--staged` against a real temporary repository, and the sample hook blocking a commit. Test
credentials are built at run time from a seeded random source ([`support/fixtures.mjs`](support/fixtures.mjs)); none is
written as a literal, so this repository passes its own scan and does not trip push protection.

`npm run lint` checks tracked files for trailing whitespace, tabs and missing final newlines.

## Licence

MIT. See [LICENSE](LICENSE).

---
Built and maintained by the [Ligatrix](https://ligatrix.com) team. We build systems like this for companies: [book a call](https://ligatrix.com/contact/sales).
