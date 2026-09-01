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
| Security Workflow Coordinator | Resume narrowly scoped finalization, key-destruction, read/unread response-expiry, approved deletion, and ciphertext-cleanup workflows | State store, scoped audit append/receipt verification, operation-scoped Key Service calls, scoped blob operations, alert interface | Original-report plaintext; interactive report browsing; arbitrary decrypt/unwrap; export generation; audit mutation; caller-chosen object selection; changing frozen Response Note bytes |
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
| Reporter Gateway | Audit Collector | Append only the approved submission event envelope | Sequencing and exact protocol owner-approved; independent review and production gates remain OPEN CRITICAL |
| Reporter Gateway | Submission coordinator / Key Service | Create/encrypt only one new submission with no decrypt capability | Sequencing APPROVED; exact report crypto PROPOSED in document 26; review and Key Service gates OPEN CRITICAL |
| Reporter Gateway | Metadata/ciphertext stores | Create only the new report records/objects required by the approved sequence | `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` APPROVED; dependent storage/crypto gates remain OPEN CRITICAL |
| Recovery Gateway | Self-hosted CAPTCHA | Validate retrieval challenge | No-JS protocol owner-approved; dependent reviews OPEN |
| Recovery Gateway | Recovery state/verifier | Uniformly authorize Ticket ID and Recovery Secret | Owner-approved construction; independent cryptographic review OPEN CRITICAL |
| Recovery Gateway | Key Service | Request one eligible in-service Response Note decrypt after approved authorization; never receive the DEK | Exact response protocol owner-approved in document 24; independent review and Key Service gates OPEN CRITICAL |
| Operator Console | Authentication/step-up service | Password/WebAuthn login and operation-bound authorization | Exact protocol PROPOSED in document 25; approval/review, hardware, workstation, and deployment gates OPEN |
| Operator Console | Audit Collector | Obtain operation-bound pre-action receipts and append outcomes | Exact protocol owner-approved in document 23; independent review and production gates OPEN CRITICAL |
| Operator Console | State authority | CLAIM/OPEN/reopen and validate current lease generation using server time | Schema may be designed; security transitions require concurrency tests |
| Operator Console | Key Service | Request in-service report-text decrypt only for the current authorized OPEN/REOPEN context; never receive key bytes | Exact report crypto PROPOSED in document 26; receipt review and Key Service policy OPEN CRITICAL |
| Operator Console | File Processing Sandbox | Request one controlled safe representation for the current lease | Exact protocol PROPOSED in document 29; owner/review and production gates OPEN |
| Operator Console | Security Workflow Coordinator | Start one fenced finalization workflow | Dependent crypto/MFA/audit gates remain OPEN |
| Operator Console | Emergency Export Worker | Start one export bound to the current OPEN lease and authorization | Exact construction PROPOSED in document 28; MFA/audit/alert and production gates remain OPEN |
| Security Workflow Coordinator | Audit Collector | Obtain required receipts and append truthful outcomes | Exact protocol owner-approved in document 23; independent review and production gates OPEN CRITICAL |
| Security Workflow Coordinator | Key Service | Perform operation-scoped create/verify/activate/expire/destroy calls for the current fenced workflow | Response protocol owner-approved in document 24; independent review and Key product/topology/policy OPEN CRITICAL |
| Security Workflow Coordinator | Metadata/ciphertext stores | Stage frozen ciphertext, publish state, or delete one scoped object | Must follow approved state machine and idempotency rules |
| Security Workflow Coordinator | Alert Service | Send an allowlisted required alert | Exact protocol PROPOSED in document 31; approval/review and production gates OPEN |
| Emergency Export Worker | Audit Collector | Obtain the export pre-action receipt and append truthful outcome | Exact protocol owner-approved in document 23; independent review and production gates OPEN CRITICAL |
| Emergency Export Worker | Key Service | Use one Report-DEK for the exact authorized export context | Key policy and export construction OPEN CRITICAL |
| Emergency Export Worker | Metadata/ciphertext stores | Read only the objects bound to the current authorized export and write one encrypted staging object | Exact streaming/staging profile PROPOSED in document 28; implementation review OPEN CRITICAL |
| Emergency Export Worker | Alert Service | Satisfy the approved administrator-notification precondition | Exact durable-acceptance protocol PROPOSED in document 31; approval/review and production gates OPEN |
| Application Administrator Console | Audit read interface | Read authorized audit evidence | Must not reuse append or retention credentials |
| Audit Collector | Independent checkpoint verifier | Publish independently verifiable evidence | RFC 9162/9942 construction and cadence owner-approved; independent review and production gates OPEN CRITICAL |
| Audit retention process | Audit Collector/store | Expire only independently eligible 365/730-day material and create controlled evidence | Exact isolated procedure PROPOSED in document 32; application/admin early expiry prohibited |

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
| Use Response-DEK capability | N | GATED in-service decrypt result only; never key bytes | N | N | GATED lifecycle operations only; never key bytes | N | N | GATED non-exportable key under policy | N | N |
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

The current Stage A submission-audit descriptor records only the approved
submission event-family order, required timing labels, authorization windows,
durable-receipt flags, and allowlisted/forbidden payload-field metadata from
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. It does not implement an Audit
Collector client, append events, create or verify receipts, inspect attempt
state, persist submission metadata, create keys, expose endpoints, or authorize
acceptance.

The current Stage A submission-attempt credential descriptor records only the
approved single-use, two-hour pre-claim lifetime, transport, forbidden binding,
minimum durable-representation, and no-log/no-audit metadata from
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. It does not generate or verify
credentials, persist credential material, install cookies, inspect requests,
claim attempts, call services, expose endpoints, or authorize
submission/report access.

The current Stage A submission-reconciliation descriptor records only the
approved crash-reconciliation timing, candidate-state, terminal-outcome,
action, persistent-cleanup-alert, and allowlisted/forbidden payload metadata
from `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. It does not implement a
reconciler, scheduler, Audit/Key/Alert Service adapter, ciphertext deletion,
state transition, endpoint, or submission authorization capability.

The current Stage A credential-response descriptor records only the approved
one-time live response and lost-response policy from
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. It does not generate credentials,
persist or redisplay a Recovery Secret, issue replacements, record
`credentials_delivered`, deduplicate by content, render a response, inspect
requests, expose endpoints, or authorize recovery/submission.

### Key Service

The Key Service exposes distinct policy operations for new-report protection, authorized report use, response protection/use, and per-object key destruction. Policy evaluation is state-aware and operation-scoped.

The interface design does not return raw DEKs to callers. Exact report and
Response Note constructions are defined/proposed in documents 26 and 24;
independent review, Key Service product/topology, and secure-memory/deployment
behavior remain OPEN CRITICAL.

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

The alert interface accepts only allowlisted event codes and system-generated
identifiers. It rejects arbitrary strings and sensitive payloads. Operations
requiring durable notification cannot claim success until the approved delivery
precondition is met. `docs/31_ADMINISTRATOR_ALERT_PROTOCOL.md` defines the owner-approved exact
closed schema, self-hosted inbox/SMTP path, synchronous durable acceptance,
idempotency, retry, acknowledgement, retention, and failure matrix; it remains
non-authorizing pending independent review and production gates.

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

During inert Stage A, a non-executing source policy fixes the exact executable
AST of `reporter_gateway/views.py` and `reporter_gateway/middleware.py`. It
therefore fails closed on added endpoint/input/persistence/cookie/logging
behavior, request-derived render context, unsafe-method acceptance, or a change
to the current restrictive cache, CSP, referrer, permissions, cross-origin, or
cross-domain response headers. The policy parses but never imports or executes
either target.

Passing this policy is source-conformance evidence only. It does not prove
browser behavior, reverse-proxy/header behavior, access-log suppression,
network anonymity, process isolation, deployment configuration, or any future
submission endpoint.

## OPEN implementation gates

| Interface area | Blocking decision |
|---|---|
| Submission Gateway to audit/key/storage | Sequencing in `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` APPROVED; dependent constructions remain OPEN CRITICAL |
| Recovery Gateway/verifier | Owner-approved encoding/verifier; independent cryptographic review and dependent gates remain OPEN CRITICAL |
| Original report protection/use | Exact construction PROPOSED in document 26; consolidated approval/review and Key Service gates OPEN CRITICAL |
| Response protection/use | Exact construction owner-approved in document 24; independent review and Key Service gates OPEN CRITICAL |
| Key Service | Exact acceptance/capability plan PROPOSED in document 27; product, topology, real PoC, and independent review OPEN CRITICAL |
| Audit receipts/checkpoints | Receipt, anti-replay, chain/batch, signatures, independent verification, alerting — OPEN CRITICAL |
| Emergency Export | Exact construction PROPOSED in document 28; owner/review, alert, signer/HSM, custody, Key Service, concurrency, workstation, and deployment gates OPEN CRITICAL |
| Administrator alerts | Exact self-hosted transport, closed schema, durable acceptance, retry/escalation, and failure policy PROPOSED in document 31; owner/review and production gates OPEN HIGH |
| Retention and deletion | 90-day unread expiry, OPEN-only operator deletion, exceptional SEALED flood ceremony, cleanup, metadata minimization, and audit expiry authority PROPOSED in document 32; owner/legal/review and production gates OPEN CRITICAL |
| Operational access/workstations | Three separate Ubuntu/Firefox device classes, exact role sessions, admin v2 step-up, export transfer broker, custodian quorum/bastion/break-glass PROPOSED in document 33; owner/review and physical production gates OPEN CRITICAL |
| File Processing Sandbox | Exact construction PROPOSED in document 29; owner/review, artifact pinning, fuzz corpus, production microVM/broker, Key Service/audit and deployment gates OPEN HIGH |
| CAPTCHA | Owner-approved no-JavaScript protocol; Pillow/font, audio/accessibility, PostgreSQL concurrency, and production-boundary reviews OPEN HIGH |
| Authentication/step-up | Exact report-bound protocol PROPOSED in document 25 and admin/workstation extension PROPOSED in document 33; owner/review and production gates OPEN HIGH |
| Alerts | Exact protocol PROPOSED in document 31; owner/review and production gates OPEN HIGH |

An OPEN gate blocks only its affected interface. It does not authorize a mock that stores plaintext, returns a fixed success receipt, exposes a permissive key call, disables verification, or silently falls back.

Current Stage A evidence includes content-free no-JavaScript CAPTCHA
descriptors and a non-executing exact-source policy for their approved static
metadata only. This evidence does not create a Challenge Service, issue or
verify challenges, render image/audio, bind requests, persist state, close the
PostgreSQL concurrency proof, or authorize Reporter/Recovery Gateway use.

Stage A also includes content-free request-admission descriptors and a
non-executing exact-source policy for the approved body/multipart/streaming/time
metadata only. This evidence does not parse HTTP or multipart data, install a
Django upload handler, create sandbox jobs, prove proxy/no-spool behavior,
preserve CSRF under the custom handler, or authorize submission endpoint use.

Stage A also includes content-free attachment-admission descriptors and a
non-executing exact-source policy for common file count, size, kind, slot,
extension, transient-filename, and trust-denial metadata. This evidence does
not inspect file bytes, parse JPEG/PNG/PDF, create sandbox jobs, persist
originals, expose safe views, encrypt attachments, or authorize upload handling.

Stage A also includes content-free safe-view descriptors and a non-executing
exact-source policy for PNG output, response-header, binding, non-durability,
and ordinary-download-denial metadata. This evidence does not decrypt original
bytes, render attachments, validate PNG output, call a sandbox, inspect leases,
serve responses, or authorize operator access.

Stage A also includes content-free file-sandbox descriptors and a non-executing
exact-source policy for microVM compute, isolation, transport, filesystem, and
credential-denial metadata. This evidence does not boot Firecracker, execute
parsers, open files, create jobs, exchange vsock messages, process attachments,
or prove a sandbox boundary.

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

## Stage A negative-capability source conformance

`architecture_checks/negative_capabilities.py` parses only
`security_interfaces/errors.py` and `security_interfaces/unavailable.py`. It
fixes the exact executable AST of the controlled dependency/error registry and
all mandatory unavailable adapters. A success return, weaker or plaintext
development fallback, added service/method, dependency reassignment,
input-bearing error, logging/import side effect, or any other executable change
fails closed pending an explicit policy review.

Missing roots, unknown targets, malformed source, and unreadable inputs produce
controlled content-free violations. Neither target is imported or executed.
Passing this policy proves only the current negative-capability source shape; it
does not prove process/network/credential isolation, service authentication,
durability, cryptography, or any real external-service integration. Every
dependent and production gate remains OPEN.

## Stage A static conformance record

`architecture_checks/` now applies exact AST import allowlists to the current
read-only `reporter_gateway` package and reporter-only root URL configuration.
The check denies every unlisted absolute import, parent-relative/star import,
and direct built-in dynamic import or code-execution call without importing or
executing scanned source. Any future dependency edge requires an explicit
reviewed policy change.

This is source-level defense-in-depth only. It does not establish production
process, credential, network, deployment, or runtime isolation and does not
authorize any currently gated edge in this document.

The next Stage A guard statically fixes the current development
`INSTALLED_APPS`/`MIDDLEWARE` security profile, the single inert reporter-home
route, a closed passive landing-template profile, and CSS without external
resource or legacy active-content constructs. Target Python is parsed as AST
and never imported; the template is parsed but never rendered. Targeted
assignments and URL patterns cannot be changed after their literal definition.

The scanner returns only controlled reason codes for missing, malformed,
dynamic, mutated, unreadable, or out-of-root input and does not copy source
snippets into violations. This remains a narrow source-review guard, not a
general HTML/CSS sanitizer, browser execution proof, settings hardening for
production, or authorization to add any protected interface.

## Stage A PostgreSQL concurrency scaffold record

The test-only scaffold fixes six current metadata races: one active report per
operator, one active lease per report and per operator, one active security
operation per report, stale report-version rejection, and stale lease-generation
rejection. It constructs only fresh ephemeral UUID metadata for 20–100 unique
contenders and records the requirement for synchronized multi-process,
dedicated-connection execution.

The scaffold has no driver, DSN, credential, executor, lock implementation, or
database mutation. Its runner returns one controlled unavailable result after
backend probing and remains unavailable when a backend capability object is
mocked as PostgreSQL-capable. Consequently, this slice is a future-test
contract only: it supplies no concurrency, durability, isolation, lock-order,
cleanup, or release evidence and closes no PostgreSQL or production gate.

## Stage A lifecycle migration conformance record

The current lifecycle migration is checked as source without importing it. The
policy requires one `0001_initial.py`, an empty dependency graph, the exact
Report/ReportLease/SecurityOperation field names and Django field constructors,
and the reviewed `CreateModel`/`AddIndex`/`AddConstraint` sequence. Any other
numbered migration, import, callable, dynamic expression, data migration, raw
SQL, model, field, or constructor fails closed with a controlled content-free
violation. Django's dry migration detector separately rejects model/migration
drift.

This policy makes a migration change review-visible. It does not prove the SQL
emitted by a selected PostgreSQL version, transaction/lock behavior, online
migration safety, rollback, backup interaction, durability, or production
deployment. Those reviews and gates remain OPEN.

## Stage A finalization sequence record

The approved `FINALIZING` order is represented as one received-request
checkpoint followed by the exact twelve actions in `docs/03`: validate OPEN
context, validate CAPTCHA, consume exact-artifact step-up, durably audit the
request, atomically commit protected staging plus `FINALIZING`, verify staging,
request and confirm Report-DEK destruction, durably audit that destruction,
publish availability, invalidate lease capabilities, and start ciphertext
deletion. Every other edge is denied.

These checkpoint names are not Report states, database rows, service receipts,
or assertions that an action happened. Plans contain only operation/report/
idempotency/operator/lease UUIDs and version/generation counters, and explicitly
authorize nothing and persist nothing. The executor always fails closed. Actual CAPTCHA,
step-up consumption, audit receipts, protected response bytes, PostgreSQL
commit, Key Service destruction, availability, invalidation, cleanup, retries,
and crash resumption remain absent and gated.

## Stage A operator-deletion sequence record

The approved OPEN-only operator-deletion order in `docs/32` is represented as
one received-request checkpoint followed by the exact ten actions: validate
the current OPEN/input/CAPTCHA context, verify step-up, durably audit the
request, lock and revalidate, commit the fenced `DELETING` workflow, invalidate
ordinary capabilities, confirm Report-DEK destruction, audit the destruction
outcome, invalidate recovery eligibility, and enter the terminal state while
starting cleanup. Every other edge is denied.

Checkpoint names are conformance labels only, not Report states, database
rows, receipts, destruction evidence, or claims that input, CAPTCHA, step-up,
audit, locking, key handling, recovery invalidation, or cleanup occurred. Plans
contain only internal operation/idempotency/report/operator/lease UUIDs and
version/generation counters. They authorize nothing, persist nothing, and
explicitly destroy no key or content. The executor always fails closed. The
real operator-deletion workflow and every legal, independent-review,
PostgreSQL, MFA, CAPTCHA, audit, Key Service, alert, cleanup, and production
gate remain OPEN.

## Stage A orchestration-source purity record

`architecture_checks/orchestration.py` parses, but never imports or executes,
the current inert finalization, OPEN-only operator-deletion, response-retention,
ciphertext-cleanup, terminal-metadata retention, and audit-retention modules. The
policy fixes the six exact target paths, imports and top-level members; closed
enum members; content-free immutable snapshot/plan fields; every false
capability flag; a closed call/raise set; and the executor signature/body whose
only outcome is its controlled unavailable exception.

Nested or altered imports, database/network/cryptographic/I/O and locally
selected time calls, dynamic/effectful syntax, attribute or subscript writes,
new content or authorization fields, and any executable executor body fail
closed with controlled source-free violations. Imported types, constants,
top-level members, and allowed call names cannot be shadowed. Response retention,
cleanup, terminal-metadata retention, and audit retention alone may read server
time and convert an already aware timestamp to UTC through their exact timezone
calls. This is static review evidence, not a runtime sandbox, semantic proof,
external-service control, or authority to finalize, recover, schedule, alert,
expire, clean up, or delete a report. Every external and production gate remains
OPEN.

## Stage A response-retention planning record

`report_lifecycle/retention.py` represents the owner-approved 90-day unread and
72-hour read-window rules using only internal UUIDs, `RESPONSE_AVAILABLE`, a
state version, and trusted timestamps. It requires the stored unread deadline
to equal exactly `response_available_at + 90 * 24 hours`; an already stored
first read must be strictly before that deadline and its stored expiry must
equal exactly `first_read_at + 72 hours`. It never proposes a first read. At
either exact deadline, expiry wins.

The result is immutable and explicitly authorizes no recovery, persists no
deadline, decrypts no response, and destroys no key or content. Its executor
always returns one controlled unavailable failure. It does not implement the
PostgreSQL first-read race, recovery authorization, audit receipt, Key Service
conversion/destruction, verifier invalidation, ciphertext cleanup, or any
reporter endpoint. All independent, legal/operational, external-service,
concurrency, and production gates remain OPEN.

## Stage A ciphertext-cleanup timing record

`report_lifecycle/cleanup.py` represents only the timing metadata approved in
`docs/32`: base delays of 5 seconds, 30 seconds, 2 minutes, then five minutes
inside the first hour, one hour until the 24-hour boundary, and six hours
thereafter without a policy retry maximum. It also fixes the 10% maximum jitter,
one-minute maximum reconciler interval, and the persistent-failure alert boundary
at exactly 15 minutes after the first failure.

The planner receives only internal cleanup/idempotency UUIDs, a bounded counter,
and trusted timestamps. It chooses no jitter and contains no target object ID,
path, filename, provider error, receipt, key, or protected data. Its immutable
plan explicitly authorizes no deletion, schedules/persists nothing, submits no
alert, and calls no service; its executor always fails closed. It does not prove
exactly-once alert acceptance, choose a cleanup scope, obtain an audit receipt,
delete ciphertext, or implement a worker/reconciler. All audit, alert, storage,
concurrency, external-service, and production gates remain OPEN.

## Stage A terminal-metadata retention planning record

`report_lifecycle/metadata_retention.py` represents only the owner-approved
minimum terminal application metadata period in `docs/32`. It accepts internal
retention/cleanup UUIDs and a trusted cleanup-confirmation timestamp. Until
cleanup is durably confirmed it returns a retain classification with no removal
time. A confirmation establishes the earliest review boundary at exactly
30 times 24 elapsed hours in UTC; equality marks only `REMOVAL_REVIEW_DUE`.

The immutable plan explicitly authorizes no removal, deletes no public Ticket
ID lookup, persists no state, schedules no job, and calls no external service.
It contains no public Ticket ID, Recovery Secret, verifier, content, filename,
path, key, or provider error. Its executor always fails closed. This does not
implement the separately credentialed retention job, a durable cleanup proof,
database deletion, generic recovery behavior, Key Service tombstone retention,
or legal/operational policy enforcement. Every dependent gate remains OPEN.

The same non-executing source policy now fixes the exact metadata-retention
target, imports, top-level members, closed disposition enum, immutable snapshot/
plan fields, all five false capability flags, allowed calls and raises,
protected binding names, and always-unavailable executor. Database deletion,
scheduler, Audit Service, Key Service, I/O, logging, mutation, dynamic syntax,
public-ticket/recovery/path/content fields, or an executable executor fail
closed. Passing is static source evidence only and closes no retention-job,
cleanup-proof, database, recovery, Key Service, legal, or production gate.

## Stage A audit-retention planning record

`report_lifecycle/audit_retention.py` represents only the exact minima approved
in `docs/23` and `docs/32`: 365 times 24 elapsed hours for event/receipt/proof
material and 730 times 24 elapsed hours for signed checkpoint, consistency,
public-key-manifest, and witness evidence. It accepts only internal retention/
evidence UUIDs, one closed evidence class, trusted collector time, and a strict
boolean stating whether retained verification still requires the evidence.

Before the minimum boundary it retains. At or after the boundary, a required
dependency still retains; otherwise the planner marks only `EXPIRY_REVIEW_DUE`.
The immutable plan authorizes no expiry, deletes no audit evidence, persists no
retention batch, exposes no witness evidence, and calls no external service. Its
executor always fails closed. This does not implement the isolated credential,
daily job, dependency graph, controlled retention record, witness interface,
database mutation, legal policy, or Audit Service. Every dependent gate remains
OPEN.

The non-executing source policy now fixes the exact audit-retention target,
imports, top-level timing and type members, both closed enums, immutable
snapshot/plan fields, all five false capability flags, allowed calls/raises,
protected binding names, and always-unavailable executor. Database expiry,
scheduler, witness, network, I/O, logging, mutation, dynamic syntax, receipt/
content/key fields, or executable executor changes fail closed. Passing is
static source evidence only and closes no clock, identity, dependency, database,
retention-batch, witness, legal, Audit Service, or production gate.

## Stage A administrative step-up v2 foundation record

`security_interfaces/administrative_step_up_descriptors.py` validates only the
version-2 fields that are exact without selecting an operation profile: 16-byte
authorization, administrator, session, and device identifiers; the existing
binding purpose and unsigned key epoch; exact non-sliding 120-second timing; and
an unused-only state.

The immutable structural result reports no complete operation profile, performs
no WebAuthn or artifact-binding verification, and authorizes neither an
administrative action nor flood deletion. It has no operation, target,
artifact-kind/binding, credential-row, challenge, handle, persistence, or
consumption field. Actor-role-specific flood profiles, MFA/session/device proof,
database concurrency, service integration, independent review, and production
gates remain OPEN.

The non-executing descriptor-source policy fixes the exact target, imports,
protocol-version and lifetime expressions, top-level member set, immutable
class profiles, false capability results, validator bodies, and closed calls.
Nested imports, dynamic constructs, added fields or members, persistence,
network, file, logging, cryptographic, or authorization behavior fail closed.
The target is parsed but never imported or executed.

Passing this source policy closes no administrator-identity, authentication,
WebAuthn, session/device, operation-profile, persistence, consumption,
concurrency, independent-review, or production gate.

## Stage A recovery credential descriptor record

`security_interfaces/recovery_descriptors.py` validates only the credential
shape facts already fixed by `docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md`: a
version-1, 16-byte Ticket ID encoded as exactly 26 uppercase unpadded RFC 4648
Base32 characters and a 32-byte Recovery Secret encoded as exactly 43 unpadded
base64url characters. The verifier purpose profile records only the approved
domain label and full 32-byte HMAC tag size.

Successful validation returns immutable, content-free shape evidence. It does
not return or retain the supplied credential text or decoded bytes, generate
credentials, compute a verifier, compare tags, persist plaintext secrets,
perform lookup, expose an endpoint, call a Recovery Verifier Service, use a
Response-DEK, or authorize recovery.

The non-executing recovery-descriptor policy fixes the exact target, imports,
constants, immutable class profiles, validator behavior, and false capability
results. Added random generation, HMAC/hash use, constant-time comparison,
persistence, network, file, logging, Django integration, lookup, endpoint, or
authorization behavior fails closed. The target is parsed but never imported or
executed.

Passing this source policy closes no credential-generation, verifier,
cryptographic-review, recovery lookup, Response-DEK, persistence,
external-service, independent-review, or production gate.

## Stage A Response Note crypto descriptor record

`security_interfaces/response_crypto_descriptors.py` validates only the static
version-1 Response Note crypto profile facts already fixed by
`docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md`: XChaCha20-Poly1305-IETF
combined-mode identifiers, 32-byte Response-DEK size, 24-byte nonce size,
16-byte tag size, 20,005-byte fixed plaintext frame, 20,021-byte
ciphertext-and-tag size, 5,000-scalar and 20,000-byte limits, immutable
context-size shapes, AAD purpose, and the six allowlisted Response-DEK
operation names.

Successful validation returns immutable profile evidence only. It does not
canonicalize Response Note text, construct plaintext frames, encode or parse
deterministic CBOR, encrypt, decrypt, compare tags, expose or hold real
Response-DEK material, retain nonce/AAD/ciphertext bytes, hold key-handle
values, persist protected bytes, call a Key Service, consume recovery
authorization, use audit receipts, inspect state rows, expose an endpoint, or
authorize response use.

The non-executing response-crypto descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added canonicalization, Unicode
normalization, frame construction, CBOR, AEAD, random generation, Key Service
calls, persistence, network, file, logging, Django integration, endpoint, or
authorization behavior fails closed. The target is parsed but never imported or
executed.

Passing this source policy closes no Response Note canonicalization,
encryption/decryption, deterministic-CBOR, Response-DEK lifecycle, Key Service,
recovery authorization, persistence, independent-review, or production gate.

## Stage A original-report crypto descriptor record

`security_interfaces/report_crypto_descriptors.py` validates only the static
version-1 original-report crypto profile facts already fixed by
`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`: XChaCha20-Poly1305-IETF
combined-mode identifiers, 32-byte Report-DEK size, 32-byte object-subkey size,
24-byte nonce size, 16-byte tag size, 20,005-byte report-text frame,
5,242,890-byte attachment frame, fixed ciphertext-and-tag sizes, object-kind
and slot metadata, immutable context-size shapes, AAD/KDF purposes, and the
seven allowlisted Report-DEK operation names.

Successful validation returns immutable profile evidence only. It does not
canonicalize report text, construct plaintext frames, derive subkeys, generate
nonces, encode or parse deterministic CBOR, encrypt, decrypt, compare tags,
expose or hold real Report-DEK/subkey material, retain nonce/AAD/ciphertext
bytes, hold key-handle values, stream original attachments, persist protected
bytes, call a Key Service, use audit receipts, inspect state rows, expose an
endpoint, or authorize report use.

The non-executing report-crypto descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added canonicalization, frame
construction, HKDF, CBOR, AEAD, random generation, Key Service calls,
attachment streaming, persistence, network, file, logging, Django integration,
endpoint, or authorization behavior fails closed. The target is parsed but
never imported or executed.

Passing this source policy closes no report-text canonicalization, attachment
admission, encryption/decryption, deterministic-CBOR, Report-DEK lifecycle,
Key Service, sandbox, storage, audit, export, deletion, independent-review, or
production gate.

## Stage A original-report schema descriptor record

`security_interfaces/report_schema_descriptors.py` validates only the ordered
metadata schema for the approved original-report AAD and ciphertext envelope
fields. It records field names, primitive categories, fixed byte sizes, public
constant values, allowed public object kinds, allowed public object slots, and
allowed public frame/ciphertext sizes only.

Successful validation returns immutable profile evidence only. It does not
encode or parse deterministic CBOR, hold report/attempt/object IDs, hold key
handles, hold nonces, hold ciphertext, call a Key Service, stream attachments,
inspect state rows, use audit receipts, persist protected bytes, expose an
endpoint, or authorize report use.

The non-executing report-schema descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added CBOR, context-value retention,
ciphertext handling, service calls, attachment streaming, persistence,
network, file, logging, Django integration, endpoint, or authorization behavior
fails closed. The target is parsed but never imported or executed.

Passing this source policy closes no deterministic-CBOR, context binding,
ciphertext handling, Key Service, sandbox streaming, persistence,
independent-review, or production gate.

## Stage A original-report text descriptor record

`security_interfaces/report_text_descriptors.py` validates only the transient
metadata profile for accepted original report text: Unicode scalar policy, NUL
and unpaired-surrogate rejection, LF line-ending profile, NFC normalization,
strict UTF-8, 5,000-scalar limit, 20,000-byte limit, and canonical UTF-8
authoritative-original metadata.

Successful validation returns immutable profile evidence only. It does not
retain browser/wire report text, return normalized text or canonical bytes,
construct plaintext frames, encrypt, persist, log, call services, create a
submission, expose an endpoint, or authorize acceptance.

The non-executing report-text descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added raw-text retention,
canonical-byte output, frame construction, encryption, persistence, logging,
network, file, Django integration, endpoint, or submission authorization
behavior fails closed. The target is parsed but never imported or executed.

Passing this source policy closes no browser/wire discard proof, canonical
byte freezing, framing, encryption, submission staging, request admission,
logging proof, independent-review, or production gate.

## Stage A original-report frame descriptor record

`security_interfaces/report_frame_descriptors.py` validates only the ordered
metadata layout for the approved original-report plaintext frames: version
byte, uint32/uint64 big-endian length fields, canonical UTF-8 report-text
payload marker, accepted-original attachment byte marker, public PDF/JPEG/PNG
kind codes, fixed text and attachment frame sizes, and zero-padding
requirements.

Successful validation returns immutable profile evidence only. It does not
accept plaintext bytes, canonicalize text, construct frames, parse frames,
validate padding bytes, inspect attachments, encrypt, decrypt, persist content,
call a Key Service, expose an endpoint, or authorize submission.

The non-executing report-frame descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added plaintext handling, frame
construction, frame parsing, padding-byte validation, attachment inspection,
encryption, persistence, network, file, Django integration, endpoint, or
submission authorization behavior fails closed. The target is parsed but never
imported or executed.

Passing this source policy closes no canonical-byte freezing, frame
construction/parsing, padding verification, encryption, submission staging,
request admission, Key Service, storage, independent-review, or production
gate.

## Stage A Response Note text descriptor record

`security_interfaces/response_text_descriptors.py` validates only the approved
static text profile for Response Notes: Unicode scalar values, NUL rejection,
LF line-ending profile, NFC normalization rule, strict UTF-8, 5,000-scalar and
20,000-byte limits, plain-text content kind, and conservative no-HTML/no-link
markers.

Successful validation returns immutable profile evidence only. It does not
return, retain, log, persist, preview, draft, frame, digest, encrypt, or bind
the supplied text or normalized text. It does not create canonical bytes,
interact with step-up, use an audit receipt, inspect report state, stage a
response, expose an endpoint, or authorize finalization.

The non-executing response-text descriptor policy fixes the exact target,
imports, constants, enum registries, immutable class profiles, validator
behavior, and false capability results. Added retained text, canonical-byte
output, digesting, drafting, persistence, network, file, logging, Django
integration, endpoint, staging, finalization, or authorization behavior fails
closed. The target is parsed but never imported or executed.

Passing this source policy closes no preview, canonical byte freezing,
artifact-binding, finalization, response staging, persistence,
independent-review, endpoint, or production gate.

## Stage A Response Note schema descriptor record

`security_interfaces/response_schema_descriptors.py` validates only the ordered
metadata schema for the approved Response Note AAD and ciphertext envelope. It
records the exact field names, primitive categories, fixed byte sizes, and
public constant values from `docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md`.

Successful validation returns immutable schema-profile evidence only. It does
not encode or parse deterministic CBOR, hold actual report, response,
finalization, key-handle, nonce, AAD, ciphertext, plaintext, receipt, recovery
authorization, or state values, call a Key Service, persist bytes, expose an
endpoint, or authorize response use.

The non-executing response-schema descriptor policy fixes the exact target,
imports, constants, enum registries, field order, immutable class profiles,
validator behavior, and false capability results. Added CBOR, retained context
values, ciphertext fields, cryptographic authentication, service calls,
persistence, network, file, logging, Django integration, endpoint, or
authorization behavior fails closed. The target is parsed but never imported or
executed.

Passing this source policy closes no deterministic-CBOR, envelope parsing,
cryptographic authentication, Response-DEK lifecycle, Key Service, recovery
authorization, persistence, independent-review, endpoint, or production gate.

## Stage A audit descriptor source-conformance record

The non-executing audit-descriptor policy fixes the complete executable AST of
`security_interfaces/audit_descriptors.py` to the reviewed inert audit-v1
profile. Any change to imports, protocol constants, event/actor registries,
authorization windows, context-dependent denial, immutable descriptor fields,
validator logic, or the false authorization result requires an explicit policy
update. Added success returns, dynamic behavior, I/O, logging, persistence,
network, cryptographic, or other side effects fail closed.

The scanner parses but never imports, executes, or echoes the target. Passing
is source-level conformance only. It does not implement deterministic CBOR,
COSE, signature or receipt verification, audit append/durability, replay
storage, protected consumers, independent review, or production capability.

## Stage A alert descriptor source-conformance record

The non-executing alert-descriptor policy fixes the complete executable AST of
`security_interfaces/alert_descriptors.py` to the inert alert-v1 profile. It
therefore locks the alert/severity/delivery registries, content-free immutable
component fields, validator logic, acknowledgement pairing, and false durable-
acceptance and protected-authorization results. Added delivery, persistence,
SMTP, logging, network, dynamic, or other effectful behavior fails closed.

The scanner parses but never imports, executes, or echoes the target. Passing
does not create a full submit request, prove durable acceptance, deliver or
acknowledge an alert, authorize a protected operation, or close PostgreSQL,
service-authentication, independent-review, Alert Service, or production gates.

## Stage A report step-up descriptor source-conformance record

The non-executing report-step-up policy fixes the complete executable AST of
`security_interfaces/step_up_descriptors.py`. It locks the version/lifetime,
ES256/EdDSA and binding-purpose registries, internal identifier/counter fields,
immutable timing and unused-only state, validator logic, and every false
WebAuthn, artifact-binding, operation-profile, and authorization result.

Added challenge, credential, handle, binding, persistence, consumption,
cryptographic, logging, network, I/O, dynamic, or success behavior fails closed.
The scanner never imports, executes, or echoes the target. Passing closes no
authentication, WebAuthn, artifact binding, session, database, concurrency,
independent-review, external-service, or production gate.
