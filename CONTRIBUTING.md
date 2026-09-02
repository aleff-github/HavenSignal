# Contributing to HavenSignal

Thank you for considering a contribution.

HavenSignal is intentionally developed more slowly than a typical web application because security-sensitive capabilities are enabled only after their requirements, trust boundaries, failure behavior, and tests are explicit.

## Before opening a pull request

Read:

1. `docs/SECURITY_CONSTITUTION.md`
2. `docs/00_PROJECT_SCOPE.md`
3. `docs/01_SECURITY_BASELINE.md`
4. `docs/02_THREAT_MODEL.md`
5. the domain-specific security document for the component you want to change.

For security-sensitive work, also read `docs/34_PRE_CODE_SECURITY_GATE.md`.

## Good contribution areas

Contributions are particularly welcome for:

- negative and abuse tests;
- concurrency tests;
- documentation corrections;
- threat-model review;
- accessibility improvements that do not expand the reporter surface;
- developer tooling;
- reproducibility;
- dependency review;
- security checks;
- narrowly scoped implementation tasks whose design is already approved.

## Please do not add

Without an explicit approved design change, do not introduce:

- reporter accounts or authentication;
- email, phone, or SMS collection;
- chat or reply threads;
- analytics or third-party telemetry;
- AI-based report classification or decision-making;
- report rankings, scoring, or accusation counting;
- ordinary operator downloads of original attachments;
- new cryptographic constructions;
- security-sensitive fallback modes.

## Development setup

```bash
python -m venv .venv
# activate the environment for your platform
python -m pip install --require-hashes -r requirements.lock
python manage.py check
python manage.py test -v 2
```

Use synthetic, non-identifying data only. Never send real reporter data,
production-sensitive material, or transformations of that material to external
development, debugging, support, review, testing, or maintenance services.

## Pull request expectations

A pull request should:

- solve one bounded problem;
- reference the relevant requirement or design document;
- state which trust boundaries are touched;
- state what data is created, read, persisted, logged, encrypted, or deleted;
- describe fail-closed behavior;
- include tests for failure and abuse cases;
- avoid unrelated refactors;
- preserve negative capabilities that are still gated;
- pass the repository CI.

For a security-sensitive change, include a short threat-impact note in the PR description.

## Commit style

Prefer small, reviewable commits with conventional prefixes such as:

- `docs:`
- `test:`
- `fix:`
- `feat:`
- `security:`
- `chore:`

Security-critical history should be easy to audit. Signed commits are encouraged.

## Vulnerabilities

Do not report exploitable vulnerabilities as normal issues. Follow `SECURITY.md`.

## Design disagreements

If code, documentation, tests, and requested behavior conflict, do not silently pick the weaker security interpretation. Raise the conflict and request an explicit project decision.

## Contributor conduct

By participating, you agree to follow `CODE_OF_CONDUCT.md`.
