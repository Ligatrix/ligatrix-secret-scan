# Contributing

Thank you for helping improve secret-scan.

## Run and test

Node.js 20 or later; there is nothing to install.

```sh
npm test                    # node:test suite
npm run lint                # whitespace, tabs, final newlines
node bin/secret-scan.mjs .  # the repository must scan clean
```

## Branches

Branch from `main` with a short descriptive name (`rule/azure-storage-key`, `fix/gitignore-negation`) and open a pull
request against `main`. Keep one change per pull request.

## Commit style

Write the subject in the imperative, under 72 characters, with no trailing full stop (« Add Azure storage key rule »).
Use the body to say why, and what it replaces if anything.

## Adding or changing a rule

1. Add the rule to `rules/default.json` with an `id`, `name`, `description`, `severity` and the tightest `pattern`
   that matches the issuer's documented format.
2. Add a true positive and a near miss to `test/rules.test.mjs`. Build test values at run time with the helpers in
   `support/fixtures.mjs` (for example `` `ghp_${rand(36)}` ``); never commit a value that looks like a live credential.
3. Add the rule to the table in `README.md` and to `CHANGELOG.md` under « Unreleased ».

## Pull request checklist

- [ ] `npm run lint` and `npm test` pass on Node.js 20 and 22
- [ ] `node bin/secret-scan.mjs .` reports no findings
- [ ] Rules changed or added have tests for both a match and a near miss
- [ ] README and CHANGELOG reflect the change
- [ ] No new runtime dependencies
