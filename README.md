# HavenSignal

**A security-first open-source system for anonymous disclosure and human guidance.**

HavenSignal is initially designed for universities and higher-education
institutions. It gives people a way to disclose a sensitive situation without
creating an account or identifying themselves, especially when they may not
know which office, professional, authority, or support channel is appropriate.

The project deliberately avoids becoming a chat platform, case-management suite, automated accusation system, or AI decision-maker. Its baseline is intentionally narrow:

**anonymous disclosure → human review → one guidance Response Note → cryptographic destruction of the original report**

> [!IMPORTANT]
> HavenSignal is under active development and is **not production-ready**. The current public reporter surface is intentionally inert and cannot receive real reports. Do not deploy the current repository to collect sensitive disclosures.

## Why HavenSignal exists

Inside universities and higher-education institutions, a person may know that
something is wrong but not know where to go next. Hierarchy, fear of
retaliation, uncertainty about procedure, and the cost of choosing the wrong
channel can make the first step difficult.

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
- [Security constitution](docs/SECURITY_CONSTITUTION.md)
- [Documentation index](docs/README.md)

## Current status

HavenSignal is in a **security-first pre-alpha implementation stage**.

The repository currently contains:

- Django 5.2.17 development scaffolding;
- an inert, read-only reporter landing page;
- an inert public status page;
- a separate fail-closed recovery gateway entry point;
- an inert fail-closed operator console entry point;
- metadata-only submission and report lifecycle models;
- pure monotonic transition planners;
- explicit fail-closed persistence boundaries;
- an inert submission `Content-Length` guard for invalid or oversized disabled
  POSTs;
- negative-capability placeholders for security services, with a non-executing
  guard that locks their exact fail-closed behavior;
- inert audit, alert, and step-up structural descriptors;
- inert no-JavaScript CAPTCHA descriptors that validate only approved metadata,
  strict identifier/answer shapes, anonymous global bucket limits, and open
  production gates;
- inert request/multipart admission descriptors that validate only approved
  body, part, header, file, streaming, timing, and closed-grammar limits;
- inert attachment-admission descriptors that validate only approved common
  file count, size, kind, slot, extension, transient-filename, and trust-denial
  metadata;
- inert safe-view descriptors that validate only approved PNG output limits,
  headers, binding metadata, and ordinary-download denials;
- inert file-sandbox descriptors that validate only approved microVM compute,
  isolation, transport, filesystem, and credential-denial metadata;
- inert original-report crypto descriptors that validate only approved Report-DEK,
  object-subkey, fixed-frame, envelope-size, object-kind, slot, and
  key-operation profile shapes;
- inert original-report schema descriptors that fix only the ordered AAD and
  ciphertext-envelope field metadata;
- inert original-report text descriptors that transiently validate only the
  approved UTF-8/NFC/LF, scalar/byte-limit, NUL/surrogate, and no-raw-copy
  profile;
- inert original-report frame descriptors that fix only approved plaintext
  frame layout metadata, public kind codes, endian markers, size fields, and
  zero-padding requirements;
- inert submission-audit descriptors that fix only the approved submission
  audit phase order, timing labels, authorization windows, and allowed/
  forbidden payload metadata;
- inert submission acceptance checkpoint descriptors that fix only approved
  Phase 0-6 checkpoint ordering, requirement labels, and forbidden runtime
  capability metadata;
- inert submission-attempt credential descriptors that fix only approved
  single-use, two-hour pre-claim, transport, non-binding, durable-representation,
  and no-log/no-audit metadata;
- inert submission-reconciliation descriptors that fix only approved scan,
  progress-deadline, cleanup-retry, persistent-alert, state/action, and
  content-free payload metadata;
- inert submission retry descriptors that fix only approved duplicate/retry
  source, one-winner/no-second-pipeline outcome, no-redisplay,
  indeterminate-response, and forbidden-signal metadata;
- inert submission failure descriptors that fix only approved failure-boundary,
  required-result, content-free, and fail-closed metadata;
- inert submission idempotency descriptors that fix only approved
  retry/concurrency scenarios, invariants, and forbidden runtime capability
  metadata;
- inert submission credential-response descriptors that fix only one-time
  display, lost-response, no-escrow, no-replacement, no-redisplay, and
  no-delivery-claim metadata;
- inert recovery credential descriptors that validate only strict Ticket ID and
  Recovery Secret encoding shapes without retaining credential material;
- inert recovery failure descriptors that fix only approved recovery
  failure-boundary, generic-result, fail-closed, and forbidden-capability
  metadata;
- inert recovery key-lifecycle descriptors that fix only approved verifier-key
  size, state, separation, forbidden-location, rotation, destruction, and
  fail-closed metadata;
- inert recovery verification descriptors that fix only approved full-length
  HMAC, constant-time comparison, boolean-only result, dummy-verification,
  generic-response, and forbidden-capability metadata;
- inert recovery verifier-record descriptors that fix only approved persisted
  record fields, full-tag size, server-controlled key ID, removal/invalidation,
  and forbidden-material metadata;
- inert recovery HMAC-message descriptors that fix only approved canonical
  domain/separator/Ticket-ID/Recovery-Secret layout metadata;
- inert Recovery Verifier Service descriptors that fix only approved
  create-only, boolean-verify, channel, output, and forbidden-capability
  metadata;
- inert recovery eligibility descriptors that fix only approved unavailable,
  unread-available, read-window, expired/destroyed, 90-day unread, 72-hour
  first-read, generic-result, and forbidden-capability metadata;
- inert recovery retrieval descriptors that fix only approved POST, CAPTCHA/
  verifier, retrieval-audit-receipt, eligibility-lock, expiry-arm, scoped
  decrypt, no-store rendering, outcome, and forbidden-capability metadata;
- inert Response Note crypto descriptors that validate only approved format,
  size, algorithm, AAD, envelope, and key-operation profile shapes;
- inert Response Note text descriptors that validate only approved plain-text,
  normalization, line-ending, scalar/byte-limit, and no-link/no-HTML rules;
- inert Response Note schema descriptors that fix only the ordered AAD and
  ciphertext-envelope field metadata;
- pure, non-executing sequence contracts for finalization and OPEN-only operator deletion;
- inert planners for Response Note expiry, ciphertext-cleanup retry timing,
  terminal-metadata review, and isolated audit-retention review;
- administrative step-up-v2 foundations that validate only content-free
  identity, timing, binding-purpose, and unused-state shapes;
- a non-executing descriptor-source guard that locks those administrative
  step-up foundations to their exact inert source profile;
- a non-executing exact-AST guard for the inert audit-v1 descriptors;
- a non-executing exact-AST guard for the inert alert-v1 descriptors;
- a non-executing exact-AST guard for inert no-JavaScript CAPTCHA descriptors;
- a non-executing exact-AST guard for inert request/multipart admission
  descriptors;
- a non-executing exact-AST guard for inert attachment-admission descriptors;
- a non-executing exact-AST guard for inert safe-view descriptors;
- a non-executing exact-AST guard for inert file-sandbox descriptors;
- a non-executing exact-AST guard for report-bound step-up-v1 descriptors;
- a non-executing exact-AST guard for inert recovery credential descriptors;
- a non-executing exact-AST guard for inert recovery failure descriptors;
- a non-executing exact-AST guard for inert recovery key-lifecycle descriptors;
- a non-executing exact-AST guard for inert recovery verification descriptors;
- a non-executing exact-AST guard for inert recovery verifier-record
  descriptors;
- a non-executing exact-AST guard for inert recovery HMAC-message descriptors;
- a non-executing exact-AST guard for inert Recovery Verifier Service
  descriptors;
- a non-executing exact-AST guard for inert recovery eligibility descriptors;
- a non-executing exact-AST guard for inert recovery retrieval descriptors;
- a non-executing exact-AST guard for inert Response Note crypto descriptors;
- a non-executing exact-AST guard for inert Response Note text descriptors;
- a non-executing exact-AST guard for inert Response Note schema descriptors;
- a non-executing exact-AST guard for inert submission-audit descriptors;
- a non-executing exact-AST guard for inert submission acceptance checkpoint
  descriptors;
- a non-executing exact-AST guard for inert submission-attempt credential
  descriptors;
- a non-executing exact-AST guard for inert submission-reconciliation
  descriptors;
- a non-executing exact-AST guard for inert submission retry descriptors;
- a non-executing exact-AST guard for inert submission failure descriptors;
- a non-executing exact-AST guard for inert submission idempotency descriptors;
- a non-executing exact-AST guard for inert submission credential-response
  descriptors;
- architecture checks that constrain the reporter-facing settings, routes,
  recovery and operator entry points, passive assets, read-only/fail-closed
  views, and restrictive response-header middleware;
- a non-executing exact-AST guard for the sole inert submission migration;
- a non-executing exact-AST guard for the inert submission state machine;
- a non-executing exact-AST guard for the inert report-lifecycle core;
- a non-executing exact-AST guard for the inert Django bootstrap entrypoints;
- a non-executing exact-AST guard for application package initializers;
- a content-free repository hygiene policy for tracked local/runtime artifacts;
- a reviewed local verification script guarded by a non-executing source policy;
- a non-executing source policy for the reviewed GitHub Actions CI workflow;
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

`docs/SECURITY_CONSTITUTION.md` is the security constitution for security-sensitive development.

Run the full reviewed local verification sequence with:

```bash
scripts/verify
```

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
