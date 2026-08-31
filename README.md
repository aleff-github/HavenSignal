# HavenSignal

**A security-first open-source system for anonymous disclosure and human guidance.**

HavenSignal is designed for people who need to disclose a sensitive situation without creating an account or identifying themselves, especially when they may not know which institution, professional, authority, or support channel is appropriate.

The project deliberately avoids becoming a chat platform, case-management suite, automated accusation system, or AI decision-maker. Its baseline is intentionally narrow:

**anonymous disclosure → human review → one guidance Response Note → cryptographic destruction of the original report**

> [!IMPORTANT]
> HavenSignal is under active development and is **not production-ready**. The current public reporter surface is intentionally inert and cannot receive real reports. Do not deploy the current repository to collect sensitive disclosures.

## Why HavenSignal exists

In complex institutions, a person may know that something is wrong but not know where to go next. Hierarchy, fear of retaliation, uncertainty about procedure, and the cost of choosing the wrong channel can make the first step difficult.

HavenSignal is intended to provide a minimal first-contact mechanism:

1. the reporter submits one free-text disclosure and, optionally, a tightly constrained set of attachments;
2. the disclosure is retained only as long as needed for human review;
3. an authorized operator reviews it inside a controlled access model;
4. the operator returns exactly one plain-text Response Note with guidance;
5. the original report key is destroyed so the sensitive source material becomes irrecoverable;
6. the reporter later retrieves only the Response Note using high-entropy recovery credentials.

The platform does **not** investigate allegations, determine guilt, provide psychotherapy, replace emergency services, or replace formal reporting channels.

## What makes HavenSignal different

HavenSignal is not trying to maximize features. It is trying to minimize the amount of sensitive material, functionality, authority, and time required to provide useful human guidance.

The design intentionally excludes:

- reporter accounts or identity verification;
- email, phone, or SMS collection;
- chat, reply threads, or two-way asynchronous messaging;
- analytics or third-party telemetry on reporter-facing surfaces;
- report aggregation, rankings, accusation counting, or automated disciplinary action;
- AI-based decisions about reports or reporters;
- ordinary operator download of original attachments;
- silent fallback to weaker security modes when required controls are unavailable.

Security-sensitive capabilities are implemented only after their corresponding design and review gates are closed. Where a mandatory security dependency is unavailable, the intended behavior is fail-closed rather than degraded operation.

## Security model at a glance

HavenSignal treats confidentiality as more important than convenience or availability.

The architecture is designed around:

- metadata minimization;
- explicit trust boundaries;
- separation of Operator, Application Administrator, and Key Custodian privileges;
- no general reporter-gateway capability to decrypt historical reports;
- short, server-authoritative operator leases and sessions;
- cryptographic deletion and non-resurrection requirements;
- durable audit receipts for protected operations;
- hostile-file handling and isolated rendering;
- no reporter-controlled data in application or audit logs;
- negative-capability interfaces that remain unavailable until approved security services exist;
- abuse and failure testing, not only happy-path testing.

The full threat model explicitly documents accepted residual risks and conditions under which guarantees do not hold.

Start with:

- [Security baseline](docs/01_SECURITY_BASELINE.md)
- [Threat model](docs/02_THREAT_MODEL.md)
- [Data lifecycle](docs/03_DATA_LIFECYCLE.md)
- [Security test plan](docs/14_SECURITY_TEST_PLAN.md)
- [Deployment trust boundaries](docs/15_DEPLOYMENT_TRUST_BOUNDARIES.md)
- [Security-service interfaces](docs/19_SECURITY_SERVICE_INTERFACES.md)
- [Pre-code security gate](docs/34_PRE_CODE_SECURITY_GATE.md)
- [Documentation index](docs/README.md)

## Current status

HavenSignal is in a **security-first pre-alpha implementation stage**.

The repository currently contains:

- Django 5.2.17 development scaffolding;
- an inert, read-only reporter landing page;
- metadata-only submission and report lifecycle models;
- pure monotonic transition planners;
- explicit fail-closed persistence boundaries;
- negative-capability placeholders for security services, with a non-executing
  guard that locks their exact fail-closed behavior;
- inert audit, alert, and step-up structural descriptors;
- pure, non-executing sequence contracts for finalization and OPEN-only operator deletion;
- inert planners for Response Note expiry, ciphertext-cleanup retry timing,
  terminal-metadata review, and isolated audit-retention review;
- administrative step-up-v2 foundations that validate only content-free
  identity, timing, binding-purpose, and unused-state shapes;
- a non-executing descriptor-source guard that locks those administrative
  step-up foundations to their exact inert source profile;
- a non-executing exact-AST guard for the inert audit-v1 descriptors;
- a non-executing exact-AST guard for the inert alert-v1 descriptors;
- a non-executing exact-AST guard for report-bound step-up-v1 descriptors;
- architecture checks that constrain the reporter-facing settings, route,
  passive assets, read-only view, and restrictive response-header middleware;
- a non-executing exact-AST guard for the sole inert submission migration;
- a non-executing exact-AST guard for the inert submission state machine;
- a non-executing exact-AST guard for the inert report-lifecycle core;
- a non-executing exact-AST guard for the inert Django bootstrap entrypoints;
- a non-executing exact-AST guard for application package initializers;
- a content-free repository hygiene policy for tracked local/runtime artifacts;
- a reviewed local verification script guarded by a non-executing source policy;
- an aggregate static architecture-policy runner used by CI;
- non-executing AST policies that keep lifecycle orchestration incapable of
  persistence, cryptography, deletion, scheduling, logging, or service calls;
- a test-only PostgreSQL concurrency scaffold.

It currently contains **no production report-submission endpoint, report-content storage, report decryption, recovery flow, operator authentication flow, file-processing pipeline, emergency export, production audit service, production Key Service, or background processing capability**.

See [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) for the detailed implementation boundary.

## Development approach

This repository uses a staged security workflow:

1. define the requirement and threat boundary;
2. document failure behavior and residual risk;
3. keep dependent capability unavailable by default;
4. implement the smallest bounded component;
5. add negative, abuse, and concurrency tests;
6. review against the security specification;
7. only then authorize the next boundary.

`AGENTS.md` is the security constitution for both human and agent-assisted development.

Run the full reviewed local verification sequence with:

```bash
scripts/verify
```

## Codex and AI use

HavenSignal uses Codex and OpenAI models as **development and maintenance tools**, not as decision-makers inside the reporting product.

Real reporter submissions, attachments, recovery material, cryptographic keys, audit artifacts, operator secrets, and any other sensitive or identifying disclosure data MUST NOT be sent to OpenAI or any other external AI service in any context. This prohibition includes product operation, development, debugging, support, issue triage, incident response, testing, and maintenance. Agent-assisted work must use only synthetic, non-identifying data.

Intended agent-assisted maintenance work includes code review, regression-test generation, specification consistency checks, secure refactoring, dependency maintenance, issue triage, documentation, and release engineering under human review.

See [CODEX_USAGE.md](docs/CODEX_USAGE.md).

## Contributing

HavenSignal welcomes careful contributions, especially in:

- security testing and negative tests;
- documentation and threat-model review;
- accessibility;
- reproducible development tooling;
- dependency and supply-chain review;
- safe deployment documentation;
- small, clearly bounded implementation tasks that already have an approved design.

Security-sensitive changes require the relevant specification review before code changes.

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [SECURITY.md](SECURITY.md) before contributing.

## Local development

Create an isolated environment and install the locked dependencies.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python manage.py check
python manage.py test -v 2
python manage.py runserver 127.0.0.1:8000
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.lock
python manage.py check
python manage.py test -v 2
python manage.py runserver 127.0.0.1:8000
```

The Django development server is for local testing only.

## Roadmap

The roadmap prioritizes independent security evidence before enabling sensitive capabilities. See [ROADMAP.md](ROADMAP.md).

## Project impact

Higher-education environments are one motivating use case, but HavenSignal is intentionally organization-agnostic. It may be useful anywhere a person faces uncertainty about where to seek help and where the first disclosure itself may be sensitive.

The project does not claim that anonymous software alone solves institutional abuse or guarantees safety. It aims to reduce one specific barrier: making a privacy-preserving first disclosure and receiving human guidance without creating a persistent conversational record.

See [PROJECT_IMPACT.md](docs/PROJECT_IMPACT.md).

## License

HavenSignal is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE).

## Security warning

Do not use the current development repository for real sensitive reports.

For vulnerabilities, follow [SECURITY.md](SECURITY.md). Do not publish exploitable security findings as ordinary GitHub issues.
