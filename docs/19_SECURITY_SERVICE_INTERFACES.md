# 19 — Security Service Interfaces and Capability Boundaries

## Status

**APPROVED — project-owner decision recorded on 2026-08-25.**

This approval establishes the capability boundaries and safe implementation
order in this document. It does not close any implementation gate listed in
`docs/12_OPEN_SECURITY_DECISIONS.md` and does not approve a cryptographic
construction, product, protocol, or deployment topology.

This document refines the conceptual boundaries in `15_DEPLOYMENT_TRUST_BOUNDARIES.md` into a minimal capability architecture. It does not approve a product, protocol, cryptographic construction, credential format, network topology, or deployment technology that remains OPEN in `12_OPEN_SECURITY_DECISIONS.md`.

Where an interface depends on an OPEN decision, this document defines only the required security properties and the capability that must be absent until approval. It must not be used as authority to invent a temporary implementation, plaintext fallback, shared superuser credential, or all-purpose service API.

## Governing requirements

This approved boundary document primarily applies:

- `SEC-CONF-001..008`;
- `SEC-LOG-001..012`;
- `SEC-ACCESS-001..015`;
- `SEC-AUTH-001..009`;
- `SEC-DEL-001..006`;
- `SEC-KEY-001..007`;
- `SEC-ROLE-001..004`;
- `SEC-RECOVERY-001..005`;
- `SEC-RESPONSE-001..008`;
- `SEC-FINALIZE-001..006`;
- `SEC-EXPORT-001..006`;
- `SEC-CAPTCHA-001..004`;
- `SEC-FILE-001..006`;
- `SEC-ALERT-001..003`;
- `SEC-BROWSER-001..002`.

`docs/01_SECURITY_BASELINE.md` remains the normative requirement registry. If this document conflicts with it or another approved decision, implementation stops and the conflict is returned to the project owner.

## Architectural rules

1. A process receives only the credentials and capabilities required for its own operations.
2. No shared application credential spans reporter, operator, administrator, audit, key-management, and sandbox roles.
3. Possession of a database, blob-store, deployment, or infrastructure credential is not sufficient to decrypt reports.
4. The Reporter Gateway cannot request existing-report plaintext or arbitrary Report-DEK use.
5. The Application Administrator cannot read reports, obtain DEKs, or impersonate an operator.
6. The Infrastructure / Key Custodian does not inherit application, operator, administrator, or audit-reader authority.
7. The application can append approved audit events but cannot update, delete, truncate, or rewrite audit history.
8. Security-sensitive disclosure, destruction, and export operations require the applicable durable audit receipt before the protected action.
9. State, lease, time, generation, idempotency, and replay decisions are server-authoritative.
10. Untrusted attachment parsing occurs only in the File Processing Sandbox.
11. Failure of a mandatory security dependency denies or suspends the protected operation; it never enables a weaker local path.
12. `FINALIZING` is a resumable multi-service protocol, not a distributed transaction.

## Capability profiles

The profiles below are deployable security identities. Multiple profiles may share a reviewed codebase, but production credentials, network policy, process identity, and runtime authority must remain distinct wherever combining them would violate a negative capability.

| Profile | Permitted responsibility | Permitted stores/services | Explicitly forbidden |
|---|---|---|---|
| Reporter Gateway | Serve anonymous submission and self-hosted challenge surfaces; transiently receive new submission plaintext | Narrow submission coordinator, scoped audit append, self-hosted CAPTCHA | Existing-report decrypt/unwrap; operator/admin capability; audit read/history mutation; arbitrary blob read; recovery-secret logging |
| Recovery Gateway | Accept Ticket ID, Recovery Secret, and CAPTCHA through POST; return a generic non-success or one eligible Response Note | Narrow recovery state lookup, approved verifier service, scoped Response-DEK use, scoped audit append | Report-DEK use; report plaintext; ticket enumeration; secret in URL/log; operator/admin capability |
| Operator Console | Authenticate operators; manage CLAIM/OPEN/reopen under current ReportLease; render controlled content; collect the final Response Note in the active session | Operator state store, scoped audit append, state-aware report-use capability, safe representations, step-up service | Audit-history mutation/read; account administration; arbitrary key use; stale-generation access; ordinary attachment download; persistent Response Note drafts |
| Application Administrator Console | Manage approved operator/account configuration; review authorized audit evidence and alerts | Administrator identity store, configuration store, audit read interface, alert status | Report/ciphertext/plaintext access; DEK operations; operator impersonation; operator factor enrollment/reset under administrator control |
| Security Workflow Coordinator | Resume narrowly scoped finalization, key-destruction, response-expiry, and ciphertext-cleanup workflows | State store, scoped audit append/receipt verification, operation-scoped Key Service calls, scoped blob operations, alert interface | Original-report plaintext; interactive report browsing; arbitrary decrypt/unwrap; export generation; audit mutation; unbounded object selection; changing frozen Response Note bytes |
| Emergency Export Worker | Build one authorized encrypted export for the operator holding the current OPEN lease | Scoped state/read capability, audit receipt, operation-bound Report-DEK use, organization public key, alert interface | Report-DEK destruction; finalization; arbitrary report selection; organization private key; plaintext artifact retention; ordinary attachment download |
| Audit Collector / Store | Durably accept allowlisted structured events; issue receipts; preserve and verify tamper evidence; expose separately authorized reads | Dedicated audit store, checkpoint signer/verifier, approved alert interface | Report content store access; arbitrary untrusted fields; application-controlled UPDATE/DELETE/TRUNCATE; DEK access |
| Key Service | Create, authorize use of, expire, and destroy per-object key capabilities under approved state and policy | Dedicated live key domain; narrow state/receipt validation dependency as approved | General caller-selected unwrap; historical per-object key backup; audit-history mutation; report DB administration; application-admin inheritance |
| File Processing Sandbox | Validate approved attachment types and create controlled temporary representations | One-job scoped input/output handles and disposable workspace | General network egress; production credentials; durable plaintext; reporter-controlled paths; broad blob/DB access; execution in Django web process |
| Metadata / Ciphertext Stores | Persist approved metadata and ciphertext under independently scoped credentials | PostgreSQL candidate; encrypted blob store | Sufficient key material for decryption; shared superuser use by application profiles; original filename persistence |
| Alert Service | Deliver approved allowlisted alerts through a self-hosted mechanism | Controlled event codes and system-generated identifiers only | Report content, operator notes, secrets, keys, original filenames, untrusted headers |
| Infrastructure / Key Custodian Plane | Operate Key Service infrastructure, live replication, and infrastructure-key lifecycle | Infrastructure control plane and approved operational evidence | Operator/admin application sessions; audit-reader inheritance; report selection or reading; arbitrary application-level decrypt |

## Minimum separation

The following separations are required before production capability is granted:

- Reporter Gateway credentials are distinct from Operator Console and Recovery Gateway credentials.
- Application Administrator Console credentials are distinct from operator credentials and cannot mint operator sessions or factors.
- Audit append, audit read, checkpoint signing, and audit retention expiry are separate authorities.
- Key creation, report-use, response-use, and key-destruction calls are operation-scoped; no application profile receives an `unwrap_any` authority.
- Finalization/key-destruction authority and Emergency Export authority use distinct service identities and policies.
- File Processing Sandbox jobs run with disposable, per-job authority and no reusable application credential.
- The emergency-export private key is absent from web and workflow processes; only the configured public key is available for approved encryption.
- Database and blob credentials are separated by profile and operation. Administrative storage access does not imply Key Service access.

Exact VM, container, namespace, service-mesh, or host placement remains subject to deployment review. Process separation without credential and network-policy separation is not sufficient.

## Django dependency boundaries

The reporter-facing `anonymous_reporting` package remains an inert bootstrap.
The internal `submission_workflow` application contains only the approved
metadata state model, database constraints, and a pure non-persisting
transition planner. It has no view, URL, protected transition executor, or
external-service adapter. The following dependency rules are not authorization
to enable their flows:

- entrypoints for reporter, recovery, operator, and administrator surfaces use separate URL configuration and deployment settings profiles before receiving production credentials;
- HTTP views call narrowly scoped application services and never call Key Service, Audit Service, blob, or sandbox vendor clients directly;
- application services depend on explicit security ports/interfaces, not on concrete vendor SDKs;
- each infrastructure adapter implements one bounded port family and receives only its own credential profile;
- ORM models and repositories do not expose decrypted content as general-purpose objects or provide unrestricted `get_report_content` helpers;
- workflow code owns idempotency and state-machine orchestration but cannot bypass the state authority, audit receipts, or Key Service policy;
- reporter modules cannot import operator, administrator, recovery-decryption, export, or existing-report key-use adapters;
- administrator modules cannot import report-content repositories, operator session creation, or key-use adapters;
- sandbox execution is a separate executable/process boundary and is not imported as an in-process parser by Django views or workers;
- disabled or unconfigured security adapters fail closed at startup or call time as appropriate; no development plaintext adapter is permitted.

A future package layout may reflect these profiles, but names and directory placement must not be mistaken for a security boundary. Import rules require automated architecture tests, while credential and network isolation require deployment tests.

## Allowed dependency graph

All edges are deny-by-default and require authenticated service identity, least-privilege policy, bounded request size, controlled error handling, and metadata-safe logging.

| Caller | Callee | Allowed purpose | Gate |
|---|---|---|---|
| Reporter Gateway | Self-hosted CAPTCHA | Generate/validate submission challenge | No-JS protocol owner-approved; rendering/audio/accessibility and production reviews OPEN |
| Reporter Gateway | Audit Collector | Append only the approved submission event envelope | Sequencing APPROVED; exact receipt protocol PROPOSED in document 23 and remains OPEN CRITICAL |
| Reporter Gateway | Submission coordinator / Key Service | Create protection capability for one new submission only | `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` APPROVED; crypto and Key Service constructions remain OPEN CRITICAL |
| Reporter Gateway | Metadata/ciphertext stores | Create only the new report records/objects required by the approved sequence | `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` APPROVED; dependent storage/crypto gates remain OPEN CRITICAL |
| Recovery Gateway | Self-hosted CAPTCHA | Validate retrieval challenge | No-JS protocol owner-approved; dependent reviews OPEN |
| Recovery Gateway | Recovery state/verifier | Uniformly authorize Ticket ID and Recovery Secret | Owner-approved construction; independent cryptographic review OPEN CRITICAL |
| Recovery Gateway | Key Service | Use one eligible Response-DEK after approved authorization | Response crypto/lifecycle OPEN CRITICAL |
| Operator Console | Authentication/step-up service | Login and operation-bound authorization | Enrollment, reset, recovery, TTL, and digest representation OPEN |
| Operator Console | Audit Collector | Obtain operation-bound pre-action receipts and append outcomes | Exact protocol PROPOSED in document 23; approval and independent review OPEN CRITICAL |
| Operator Console | State authority | CLAIM/OPEN/reopen and validate current lease generation using server time | Schema may be designed; security transitions require concurrency tests |
| Operator Console | Key Service | Use one Report-DEK only for the current authorized OPEN/REOPEN context | Receipt and Key Service policy OPEN CRITICAL |
| Operator Console | File Processing Sandbox | Request one controlled safe representation for the current lease | PDF/image profile and sandbox OPEN |
| Operator Console | Security Workflow Coordinator | Start one fenced finalization workflow | Dependent crypto/MFA/audit gates remain OPEN |
| Operator Console | Emergency Export Worker | Start one export bound to the current OPEN lease and authorization | Export crypto/MFA/audit/alert gates remain OPEN |
| Security Workflow Coordinator | Audit Collector | Obtain required receipts and append truthful outcomes | Exact protocol PROPOSED in document 23; approval and independent review OPEN CRITICAL |
| Security Workflow Coordinator | Key Service | Perform operation-scoped create/use/destroy calls for the current fenced workflow | Key product/topology/policy OPEN CRITICAL |
| Security Workflow Coordinator | Metadata/ciphertext stores | Stage frozen ciphertext, publish state, or delete one scoped object | Must follow approved state machine and idempotency rules |
| Security Workflow Coordinator | Alert Service | Send an allowlisted required alert | Transport and durable semantics OPEN |
| Emergency Export Worker | Audit Collector | Obtain the export pre-action receipt and append truthful outcome | Exact protocol PROPOSED in document 23; approval and independent review OPEN CRITICAL |
| Emergency Export Worker | Key Service | Use one Report-DEK for the exact authorized export context | Key policy and export construction OPEN CRITICAL |
| Emergency Export Worker | Metadata/ciphertext stores | Read only the objects bound to the current authorized export | Export format and plaintext cleanup OPEN CRITICAL |
| Emergency Export Worker | Alert Service | Satisfy the approved administrator-notification precondition | Transport and durable semantics OPEN |
| Application Administrator Console | Audit read interface | Read authorized audit evidence | Must not reuse append or retention credentials |
| Audit Collector | Independent checkpoint verifier | Publish independently verifiable evidence | RFC 9162/9942 construction and cadence PROPOSED in document 23; approval/review OPEN CRITICAL |

No other edge is implicitly allowed. In particular, the Application Administrator Console, Reporter Gateway, and File Processing Sandbox have no general edge to report-key use.

## Capability matrix

Legend: `Y` is required by an approved flow; `N` is prohibited; `GATED` means the capability must remain absent until its named OPEN decision is approved.

| Capability | Reporter | Recovery | Operator | App Admin | Workflow | Export | Audit | Key | Sandbox | Key Custodian |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Receive new report text transiently | GATED | N | N | N | N | N | N | N | N | N |
| Receive attachment plaintext for validation | GATED transit only | N | N | N | N | N | N | N | GATED one job | N |
| Read existing original report plaintext | N | N | GATED | N | N | GATED current export only | N | N | GATED one object/job | N |
| Read Response Note plaintext | N | GATED one authorized response | N | N | N | N | N | N | N | N |
| Create per-object protection capability | GATED new report only | N | N | N | GATED response only | N | N | GATED under policy | N | N |
| Use Report-DEK capability | N | N | GATED current lease/receipt only | N | N | GATED current export only | N | GATED under policy | N | N |
| Use Response-DEK capability | N | GATED valid recovery only | N | N | GATED lifecycle maintenance only | N | N | GATED under policy | N | N |
| Destroy per-object DEK | N | N | N | N | GATED fenced workflow only | N | N | GATED under policy | N | Infrastructure only, not object selection |
| Append audit events | GATED scoped schema | GATED scoped schema | GATED scoped schema | GATED admin schema | GATED scoped schema | GATED export schema | Y | N | GATED result code only | GATED infrastructure schema |
| Read audit history | N | N | N | Y authorized view | N | N | Y | N | N | N |
| Rewrite audit history | N | N | N | N | N | N | N | N | N | N |
| Manage operator accounts | N | N | N | Y without impersonation | N | N | N | N | N | N |
| Parse untrusted attachments | N | N | N | N | N | N | N | N | GATED | N |

`GATED` does not authorize an implementation. It identifies the profile that may eventually receive the narrowly scoped capability after every referenced gate is closed.

## Cross-service request envelope

Security-sensitive calls require a canonical, versioned envelope whose exact byte representation and authentication mechanism must be approved before implementation. At minimum, the semantic fields are:

- protocol and schema version;
- authenticated caller service identity;
- allowlisted operation code;
- system-generated report/ticket identifier where applicable;
- current report state and state version;
- current ReportLease identifier and generation where applicable;
- server-issued idempotency identifier;
- server-authoritative issue/expiry times where applicable;
- applicable audit receipt identifier/evidence;
- applicable step-up authorization reference;
- exact artifact digest where required;
- nonce or anti-replay context;
- allowlisted outcome/reason code.

The envelope must not contain report text, attachment bytes, Recovery Secrets, original filenames, arbitrary operator notes, untrusted headers, or raw exception messages. Sensitive payload transfer, where unavoidable, uses a separately reviewed bounded channel and is never copied into the control envelope or logs.

Unknown fields, unknown versions, wrong caller identities, stale state versions, stale lease generations, expired authorizations, duplicate non-idempotent operations, and receipt/context mismatches fail closed.

## Interface families

### State and lease authority

The state authority owns concurrency-safe transitions and server time. It must:

- enforce one active report per operator and one active lease per report;
- issue random lease identifiers and monotonic generation/fencing tokens;
- reject stale tabs, sessions, delayed calls, and retries;
- use database transactions, locking/version checks, and uniqueness constraints;
- freeze the exact Response Note bytes on committed entry to `FINALIZING`;
- prevent OPEN, reopen, editing, and export after that transition.

It must not treat browser state, cookies alone, queue delivery, or caller-provided time as authoritative.

### Audit append and receipt

The append interface accepts only versioned event types and allowlisted fields. Its caller credential is restricted by event family. It returns a durable receipt only after the event is durably accepted.

Receipt validation must bind the caller/operator, report, operation, current state/version, lease generation where applicable, and anti-replay context. The exact receipt, chain, checkpoint, and signing constructions remain OPEN CRITICAL.

Read access uses a different service identity and interface. Retention expiry is collector-controlled. No application credential can update, delete, truncate, backdate, or accelerate expiry of historical events.

### Key Service

The Key Service exposes distinct policy operations for new-report protection, authorized report use, response protection/use, and per-object key destruction. Policy evaluation is state-aware and operation-scoped.

The interface design must not assume that raw DEKs are returned to callers. Exact cryptographic placement, wrapping, nonce/AAD construction, key derivation, verifier, and secure-memory behavior remain OPEN CRITICAL.

The service must reject:

- a reporter-profile request to use an existing Report-DEK;
- a report-use request without the required receipt and current lease generation;
- an object, operation, state, or caller mismatch;
- use after server-authoritative expiry or confirmed destruction;
- a request through a stale replica or rollback state;
- any general enumeration or `unwrap_any` request.

### Ciphertext and blob operations

Objects use server-generated identifiers. Original filenames never become storage paths or durable metadata. Credentials distinguish create, read-one, write-one, and delete-one operations; broad list/read/delete authority is not given to web profiles.

Plaintext must not be durably spooled by reverse proxies, Django upload handlers, queues, workers, or export packaging. Exact upload and temporary-storage behavior remains blocked by the applicable file and aggregate-size decisions.

### File Processing Sandbox

A job is bound to one system-generated object identifier, one operation, one lease/workflow context, explicit resource ceilings, and a short expiry. The sandbox returns only:

- a controlled safe-representation handle;
- an allowlisted rejection/failure code;
- bounded system-generated metrics approved for logging.

It never returns parser exception text, embedded metadata, or reporter-controlled filenames to logs/audit. Network access, production credentials, reusable storage credentials, and durable workspace reuse are prohibited. PDF/image jobs remain disabled until their profiles and sandbox are approved.

### Authentication and step-up

Operator and Application Administrator authentication use distinct authorization policies. Administrator account-management capability cannot issue, replace, or recover an operator factor in a way that permits impersonation.

Step-up authorization is single-use and bound to operator, ticket, operation, nonce, issue/expiry time, used state, and exact artifact digest where applicable. Exact TTL, canonical bytes/digest, enrollment, reset, recovery, revocation, and replacement remain OPEN.

### Alert delivery

The alert interface accepts only allowlisted event codes and system-generated identifiers. It rejects arbitrary strings and sensitive payloads. Operations requiring durable notification cannot claim success until the approved delivery precondition is met. Exact transport, durability, retry, and failure policy remain OPEN.

## Finalization ownership

The Security Workflow Coordinator may resume only the approved frozen workflow:

1. validate current OPEN lease and state version;
2. validate CAPTCHA and consume exact-artifact step-up authorization;
3. obtain the durable `FINALIZATION_REQUESTED` receipt;
4. commit the exact protected Response Note bytes and `FINALIZING` transition together;
5. verify durable staging while keeping the response invisible;
6. request and durably confirm Report-DEK destruction;
7. obtain durable audit evidence for `REPORT_KEY_DESTROYED`;
8. publish `RESPONSE_AVAILABLE` and invalidate every report lease capability;
9. initiate scoped original-ciphertext deletion with retry and alert behavior.

The coordinator has no authority to change the staged Response Note, return the report to OPEN, create a replacement Report-DEK, bypass a missing receipt, or publish availability before confirmed and audited destruction.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Audit append/receipt unavailable | Deny disclosure, destruction, export, or other receipt-gated action; do not perform first and audit later |
| Key Service unavailable | Deny protected use; keep resumable state without plaintext fallback or local key cache |
| Receipt invalid, stale, or context-mismatched | Deny the protected operation and record only an approved failure event if safely possible |
| State/version/lease generation conflict | Reject the request; never allow the caller or UI to choose the winner |
| Response staging fails before `FINALIZING` commit | Keep report OPEN and original key intact; require new authorization for retry |
| Crash after committed `FINALIZING` | Resume only the frozen idempotent workflow; ordinary access remains denied |
| Key destruction confirmed but later step fails | Never recreate or reopen the report; resume audit/availability completion |
| Ciphertext deletion fails after key destruction | Preserve cryptographic destruction; retry physical deletion and alert as approved |
| Sandbox parser uncertainty/error/limit | Reject the attachment/job; no in-process or less strict fallback |
| CAPTCHA unavailable for a mandatory flow | Deny the operation; no third-party or fingerprinting fallback |
| Alert dependency unavailable | Follow the still-OPEN approved per-operation policy; do not invent best-effort semantics |
| Unknown protocol/version/operation | Deny and expose only a controlled system error identifier |

## Credential and storage isolation

Production requires separate credentials for at least:

- reporter metadata create operations;
- operator state transitions and scoped reads;
- workflow state transitions;
- recovery-state lookup;
- blob create, scoped read, and scoped delete;
- audit append by event family;
- audit read;
- audit checkpoint signing;
- audit retention expiry;
- Key Service operation families;
- alert submission;
- administrator account/configuration management.

No credential is embedded in source control, URLs, client-side storage, audit events, or reporter-visible responses. Rotation and recovery must preserve negative capabilities and must not resurrect destroyed DEKs.

## Logging boundary

Every profile uses an explicit logging schema. Logs may contain only controlled operational fields such as service name, allowlisted event code, system-generated correlation identifier, result class, and bounded timing data approved for the surface.

Reporter IP address, User-Agent, request body, report text, attachment data, Recovery Secret, keys, original filenames, protected operator notes, arbitrary query values, arbitrary headers, and raw untrusted exceptions are prohibited.

Reporter-facing proxy, application, and upstream infrastructure configuration must be reviewed end to end; disabling logging only in Django is insufficient for `SEC-ANON-002`.

## OPEN implementation gates

| Interface area | Blocking decision |
|---|---|
| Submission Gateway to audit/key/storage | Sequencing in `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` APPROVED; dependent constructions remain OPEN CRITICAL |
| Recovery Gateway/verifier | Owner-approved encoding/verifier; independent cryptographic review and dependent gates remain OPEN CRITICAL |
| Response protection/use | AEAD, nonce, AAD, derivation/separation, wrapping, representation, lifecycle — OPEN CRITICAL |
| Key Service | Product, topology, state-aware policy, replication, backup, and non-resurrection proof — OPEN CRITICAL |
| Audit receipts/checkpoints | Receipt, anti-replay, chain/batch, signatures, independent verification, alerting — OPEN CRITICAL |
| Emergency Export | Encryption format, signed manifest, key identifiers, rotation, signing-key lifecycle — OPEN CRITICAL |
| File Processing Sandbox | PDF/image profiles, tools, decoded-resource limits, sandbox and temporary lifecycle — OPEN HIGH |
| CAPTCHA | Owner-approved no-JavaScript protocol; Pillow/font, audio/accessibility, PostgreSQL concurrency, and production-boundary reviews OPEN HIGH |
| Authentication/step-up | TTL, canonical artifact bytes/digest, enrollment/reset/recovery/revocation — OPEN HIGH |
| Alerts | Transport, durable acceptance, retries, escalation, dependency failure — OPEN MEDIUM |

An OPEN gate blocks only its affected interface. It does not authorize a mock that stores plaintext, returns a fixed success receipt, exposes a permissive key call, disables verification, or silently falls back.

## Architecture conformance tests

Before a profile receives production credentials, automated and operational tests must prove:

- every forbidden edge is denied by network and service authorization policy;
- Reporter Gateway cannot use existing Report-DEKs;
- Application Administrator cannot obtain content, DEKs, operator sessions, or operator-controlled factors;
- Infrastructure / Key Custodian cannot select or read reports through application interfaces;
- wrong caller, report, operation, state, lease generation, receipt, nonce, or artifact digest is rejected;
- application credentials cannot mutate audit history or accelerate retention expiry;
- stale replicas and restored backups cannot make destroyed keys usable;
- sandbox has no network, production credential, broad filesystem, or reusable object-store authority;
- mandatory dependency failure remains fail closed;
- logs and alerts reject untrusted or sensitive fields;
- finalization resumes correctly at every documented crash point;
- service credentials are not interchangeable across profiles.

These tests supplement, and do not replace, `14_SECURITY_TEST_PLAN.md` and `18_SECURITY_REVIEW_CHECKLIST.md`.

## Safe implementation order after approval

1. Define inert interface types and deny-by-default test doubles that always fail closed.
2. Add architecture-conformance tests for negative capabilities before real integrations.
3. Implement only an interface whose OPEN gate has been closed and whose failure tests are approved.
4. Grant one narrowly scoped development credential/profile at a time.
5. Run the applicable security checklist and abuse/failure tests before enabling the next edge.

No step in this order authorizes report submission, recovery, key management, audit receipts, authentication, file processing, finalization, export, or deletion by itself.
