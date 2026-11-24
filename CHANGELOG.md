# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-24

### Added

- `secret-scan` command (`bin/secret-scan.mjs`) with exit codes 0 (clean), 1 (findings) and 2 (usage or configuration error).
- Seventeen rules in `rules/default.json`: private key blocks (RSA, EC, DSA, OpenSSH, PKCS#8, PGP), AWS access key IDs
  and secret keys linked as pairs, GitHub classic and fine-grained tokens, Stripe live and restricted keys, Slack tokens
  and webhook URLs, Google API keys, Twilio API keys and auth tokens, SendGrid keys, JSON Web Tokens, database URLs
  with passwords, generic credential assignments and committed `.env` files.
- Shannon-entropy scoring, stopwords and validators to cut false positives.
- Directory walk with a `.gitignore` matcher (nested files, negation, `**`, character classes, `.git/info/exclude`),
  binary detection and a size limit.
- `--staged` mode that scans the staged blobs listed by `git diff --cached`.
- Allowlisting through `.secretscanignore` (globs, `fingerprint:` and `rule:` entries) and inline
  `secret-scan:allow` / `secret-scan:allow-next-line` comments.
- Output formats: text with masked values, JSON, and SARIF 2.1.0 for code scanning upload.
- Sample `hooks/pre-commit`, a runnable demo (`examples/demo.mjs`) and a library API with TypeScript declarations.

[1.0.0]: https://github.com/Ligatrix/ligatrix-secret-scan/releases/tag/v1.0.0
