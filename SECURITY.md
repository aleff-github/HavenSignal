# Security Policy

HavenSignal is a security-critical project intended to handle a class of information for which confidentiality failures may cause serious real-world harm.

The repository is currently **pre-alpha and not production-ready**. The current reporter surface must not be used to collect real sensitive disclosures.

## Reporting a vulnerability

**Do not open a public GitHub issue for a vulnerability that could expose sensitive content, bypass authorization, weaken cryptographic deletion, compromise recovery credentials, tamper with audit evidence, escape file isolation, or otherwise create an exploitable security condition.**

Preferred reporting channel:

1. Use GitHub's **Private Vulnerability Reporting / Security Advisory** flow for this repository when available.
2. If private reporting is unavailable, contact the repository maintainer privately through the maintainer's GitHub profile and request a private disclosure channel before sending exploit details.

Do not include real reporter data, real credentials, production secrets, or identifying victim information in a vulnerability report.

## What to include

A useful report should contain, where possible:

- affected commit or version;
- affected component;
- security property that is violated;
- minimal reproduction using synthetic data;
- expected versus observed behavior;
- realistic impact;
- prerequisite privileges or deployment assumptions;
- suggested mitigation, if known.

Please avoid destructive testing against systems you do not own or have explicit permission to test.

## High-priority classes

The following classes are treated as release blockers when applicable:

- disclosure of report text or attachments;
- unauthorized report decryption or key use;
- recovery-secret or verifier exposure;
- operator authentication or authorization bypass;
- violation of role separation;
- resurrection of cryptographically deleted report material;
- audit-log tampering or bypass of required durable receipts;
- file-processing sandbox escape or unsafe original-file exposure;
- cross-report or stale-lease authorization;
- reporter-controlled data entering application or audit logs;
- security-sensitive fallback to a weaker mode.

## Disclosure process

The maintainers will make a best effort to:

- acknowledge a complete private report within 7 days;
- reproduce and classify the issue;
- coordinate remediation before public disclosure when the report is valid;
- credit the reporter if requested and appropriate;
- publish a security advisory when doing so does not create avoidable risk.

Timelines may vary with severity, complexity, maintainer availability, and whether independent security review is required.

## Supported versions

There is currently no production release. Security fixes target the active development branch and any future explicitly supported release lines.

| Version | Supported |
| --- | --- |
| `main` development line | Yes |
| Production deployments | None currently supported |

## Development security rules

Contributors must not:

- commit production secrets;
- use real sensitive reports in fixtures or tests;
- log reporter-controlled content, secrets, recovery credentials, cryptographic keys, original filenames, or request bodies;
- disable CSRF, authentication, security headers, or other security controls merely to make tests pass;
- serve uploaded originals directly from a public webroot;
- introduce third-party telemetry on reporter-facing or operator-sensitive paths;
- add plaintext or weaker-security fallbacks for unavailable mandatory controls;
- implement a sensitive endpoint without negative and abuse tests.

`AGENTS.md` and the security documents under `docs/` are normative for security-sensitive changes.

## Safe test data

Use only synthetic, non-identifying test content.

## Scope note

HavenSignal does not promise confidentiality against every possible compromise. Accepted residual risks and out-of-scope cases are documented in [docs/02_THREAT_MODEL.md](docs/02_THREAT_MODEL.md).
