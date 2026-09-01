# 20 — Submission Acceptance, Audit, and Credential Delivery

## Status

**APPROVED — project-owner decision recorded on 2026-08-25.**

This approval establishes the sequencing, retry, lost-response, state,
audit-phase, and reconciliation policy in this document. It does not authorize
a submission endpoint: every dependent security construction listed below
remains independently blocking.

This document resolves sequencing semantics only. It does not select or approve
a CAPTCHA, cryptographic construction, Key Service, audit receipt format,
recovery verifier, file parser, sandbox, aggregate request limit, or deployment
topology. Each dependent OPEN decision remains independently blocking.

The current implementation may model these states and validate transitions
without persisting a protected transition. A database transition executor,
reconciler, form, and endpoint remain absent until their dependent gates and
PostgreSQL concurrency/failure tests are complete.

## Governing requirements

This approved protocol applies primarily to:

- `SEC-CONF-001..008`;
- `SEC-ANON-001..004`;
- `SEC-LOG-001..005`, `SEC-LOG-009..012`;
- `SEC-KEY-001..007`;
- `SEC-RECOVERY-001..005`;
- `SEC-CAPTCHA-001..004`;
- `SEC-FILE-001..006`;
- `SEC-INPUT-001..006`.

`docs/01_SECURITY_BASELINE.md` remains normative. A conflict stops
implementation and returns the decision to the project owner.

## Security outcome

A submission is accepted only when all of the following are true:

1. the mandatory self-hosted challenge and request controls succeeded;
2. report text and every accepted attachment are durably stored only as
   ciphertext under one independent Report-DEK;
3. durable metadata refers only to complete, verified ciphertext objects;
4. the required truthful audit events have durable receipts;
5. the database has committed the report to `SEALED` exactly once;
6. recovery state is durably bound to the same report without storing the
   Recovery Secret in plaintext;
7. the one-time credential-response opportunity is irreversibly consumed with
   acceptance, whether or not the response reaches the browser.

Anything short of all seven conditions is not an accepted report and must not
be claimable, openable, recoverable, or represented to the reporter as accepted.

## Trust boundaries

The flow crosses:

- reporter browser to Reporter Gateway;
- Reporter Gateway to the self-hosted challenge service;
- Reporter Gateway to the Audit Collector;
- Reporter Gateway/submission coordinator to the Key Service;
- submission coordinator to metadata and ciphertext stores;
- the crash reconciler to narrowly scoped audit, key-destruction, and
  ciphertext-deletion operations.

No boundary receives a general read, list, decrypt, unwrap, or historical audit
mutation capability. The crash reconciler never receives report plaintext or a
general Report-DEK-use capability.

## Approved decisions

### One server-authoritative submission attempt

The form carries one opaque, high-entropy submission-attempt credential created
by the server for that form instance. It is:

- single-use and short-lived;
- submitted only in the POST body and/or a protected same-site cookie, never in
  a URL;
- independent of report content, Ticket ID, Recovery Secret, IP address, and
  User-Agent;
- never logged or written to audit;
- represented durably only by the minimum verifier/index needed to enforce one
  attempt;
- protected by a database uniqueness constraint and row/state-version checks.

The exact encoding, verifier, cookie/form binding, and expiry remain part of the
project-owner decision. The credential is not a reporter account, recovery
credential, tracking identifier, or authorization to read a report.

Only the first valid request may own the attempt. Parallel copies, delayed
requests, proxy retries, browser retries, and stale tabs cannot start a second
pipeline for the same attempt.

### Pre-acceptance staging is not `SEALED`

Encrypted objects and controlled metadata may require durable staging while
independent services complete. A staged object is not yet a report in the main
lifecycle and must remain invisible to reporter recovery and operator queues.

Approved internal attempt states are:

```text
READY -> PROCESSING -> CIPHERTEXT_STAGED -> AUDIT_CONFIRMED -> ACCEPTED
                    \-> ABORTING -> ABORTED
```

`ACCEPTED` commits the report to `SEALED`. There is no transition from
`ABORTING` or `ABORTED` to `ACCEPTED`; a new form and attempt are required.
State transitions use server time, a monotonically increasing version, database
transactions, and uniqueness constraints. Browser state never chooses the
winner.

### Two truthful audit phases

The approved protocol adds these controlled event families:

- `SUBMISSION_ACCEPTANCE_REQUESTED`: durably accepted before creation of a
  Report-DEK or durable report material;
- `SUBMISSION_RECEIVED`: durably accepted only after all ciphertext and metadata
  are verified and ready for the `SEALED` commit;
- `SUBMISSION_ACCEPTANCE_FAILED`: appended where safely possible when the
  pipeline aborts, without delaying required destruction or cleanup.

Receipts bind only approved system-generated identifiers, event/operation code,
attempt state/version, caller identity, idempotency context, and anti-replay
context. They never contain report text, filenames, file metadata, Recovery
Secret, keys, request headers, or raw errors.

The exact receipt and checkpoint construction remains OPEN CRITICAL. No fixed or
local-success receipt is permitted.

### Credential response loss favors confidentiality

The approved baseline does not escrow the Recovery Secret for replay and
does not issue replacement credentials.

If `SEALED` commits but the response is lost, the report remains accepted and
the reporter may be unable to recover the future Response Note. A retry carrying
the same submission-attempt credential must not create another report and must
not re-display or replace the Recovery Secret. It returns a controlled
indeterminate-outcome response that does not claim credential delivery.

This is an explicit availability loss chosen to avoid:

- durable plaintext Recovery Secret storage;
- a credential re-display oracle;
- unsafe duplicate submissions from automatic POST retry;
- content hashing or deduplication that could correlate reports;
- a provisional credential-envelope cryptographic protocol.

The project owner explicitly accepted this residual risk on 2026-08-25. A
future replayable delivery design would require a separate approved
cryptographic construction and would supersede this decision.

## Approved sequence

### Phase 0 — serve the inert form

1. Serve only self-hosted HTML/CSS with no analytics or third-party resources.
2. Issue the submission-attempt credential and CSRF protection without reporter
   account, fingerprinting, IP binding, localStorage, IndexedDB, or service
   worker use.
3. Apply no-store, restrictive CSP, no-referrer, clickjacking, and MIME-sniffing
   protections.

### Phase 1 — admit the request

4. Accept only POST at a fixed URL with no secret or report identifier in the
   query string.
5. Reject the request at the outermost reviewed proxy/body boundary when the
   approved aggregate size or framing rules fail.
6. Validate CSRF, the current attempt credential, and the mandatory self-hosted
   challenge. Unknown, expired, consumed, or concurrently owned attempts fail
   closed.
7. Claim the attempt in one database transaction before security services or
   durable report storage are invoked.

The endpoint remains disabled until the exact aggregate request limit, CAPTCHA,
and request-upload handling are approved. Django's default temporary upload
handler is not acceptable because it may durably spool reporter plaintext.

`docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md` defines the owner-approved exact outer
and multipart limits, streaming/no-retry proxy behavior, bounded custom Django
handler, and no-spool verification. It remains non-authorizing pending its
independent production gates.

### Phase 2 — validate transient input

8. Enforce the approved text and attachment counts/sizes using server-observed
   bytes, not browser declarations.
9. Discard the original filename after immediate validation. Never use it as a
   path, identifier, log field, audit field, or operator-visible label.
10. Treat MIME, extension, Content-Type, magic bytes, and metadata as untrusted.
11. Send attachment validation only to the approved isolated sandbox using one
    attempt-scoped job and disposable plaintext handling.

PDF and image branches remain disabled until their separate structural,
resource, toolchain, sandbox, and temporary-lifecycle gates are approved. There
is no in-process or text-only fallback that silently drops submitted files.

### Phase 3 — obtain pre-action audit evidence

12. Append `SUBMISSION_ACCEPTANCE_REQUESTED` using only allowlisted metadata.
13. Stop before key creation if the durable receipt is missing, invalid, stale,
    replayed, or context-mismatched.

### Phase 4 — protect and stage

14. Generate the independent Ticket ID and Recovery Secret using the separately
    approved construction; keep the Recovery Secret transient.
15. Request a new-report-only protection capability from the Key Service. The
    Reporter Gateway cannot use existing Report-DEKs or call a general unwrap.
16. Encrypt report text and accepted original attachment bytes before any
    durable storage. Plaintext is not placed in filesystem, queue, database,
    blob, swap-backed application cache, or framework upload temporary files.
17. Write ciphertext using server-generated object identifiers and narrow
    create-only credentials.
18. Verify completeness and durability of every ciphertext object.
19. In one database transaction, persist controlled metadata, recovery verifier
    state, ciphertext references, the attempt version, and the pre-action receipt
    reference as `CIPHERTEXT_STAGED`. The row is not operator/recovery visible.

The exact report AEAD, nonce/AAD, subkey, fixed-frame, and ciphertext-envelope
construction is owner-approved in
`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`. It remains non-authorizing
pending independent review, Key Service, verifier, and durability gates.

### Phase 5 — audit and commit acceptance

20. Append truthful `SUBMISSION_RECEIVED` only after staged ciphertext and
    metadata are durably verified; obtain its durable receipt.
21. Re-lock the attempt/metadata rows, validate the expected state/version and
    both receipt contexts, and atomically commit:
    - main report state `SEALED`;
    - attempt state `ACCEPTED`;
    - immutable binding to the accepted audit receipt;
    - irreversible consumption of the one-time credential-response opportunity.
22. Only after that commit, the still-live request may write the no-store
    success response containing the Ticket ID and Recovery Secret. No other
    request or reconciler may reconstruct or issue that response.

The application must not record `credentials_delivered`. It can know that a
response was generated or attempted, but cannot prove the reporter received or
saved it.

### Phase 6 — reconcile without plaintext

23. A narrowly scoped reconciler finds nonterminal attempts by controlled state
    and server time; it never scans report content.
24. If durable evidence proves all acceptance preconditions, it may complete
    only the already-determined idempotent transition. Because it has no
    Recovery Secret, this can produce an accepted report whose credential
    response is unavailable; it never creates replacement credentials.
25. Otherwise it transitions to `ABORTING`, destroys the attempt's Report-DEK,
    retries scoped ciphertext/metadata deletion, and ends at `ABORTED`.
26. Cleanup failures remain fail-closed, are retried, and use only approved
    controlled audit/alert metadata. A staged report never becomes operator
    visible merely to improve availability.

## Failure matrix

| Failure boundary | Required result |
|---|---|
| Unsupported method, framing, size, CSRF, CAPTCHA, or attempt | Reject before acceptance; no fallback or third-party challenge |
| Parallel requests for one attempt | One database winner; all others perform no key/storage/audit pipeline |
| Audit REQUESTED unavailable | No key or durable report content created |
| Validation/sandbox uncertainty | Reject; no less strict parser or in-process fallback |
| Key Service unavailable | No plaintext persistence; attempt aborts |
| Encryption/staging failure | Report remains non-visible; destroy scoped key and staged objects |
| Metadata transaction failure | No `SEALED`; reconcile/destroy staged material |
| `SUBMISSION_RECEIVED` audit unavailable | Keep non-visible staging only long enough for approved reconciliation; never return credentials |
| Crash after final receipt but before `SEALED` | Reconciler may finish only after verifying exact receipt/state/object bindings |
| Crash after `SEALED` but before/during response | Keep one accepted report; never reissue credentials or create a duplicate for the same attempt |
| Duplicate/stale retry after acceptance | Controlled indeterminate response; no report content, status oracle, or credential re-display |
| Key/ciphertext cleanup failure | Keep data inaccessible, retry, and alert under the approved policy |
| Unknown state/version/receipt | Fail closed and require operator/security review; never guess a transition |

## Concurrency and idempotency tests required before enablement

Tests must exercise sequential retries and tightly synchronized parallel copies
at every transition. At minimum they prove:

- exactly one attempt owner and at most one `SEALED` report per attempt;
- database uniqueness remains authoritative across multiple application
  processes;
- no duplicate Report-DEK, metadata row, ciphertext object, or acceptance event
  survives reconciliation;
- a stale version cannot append a usable receipt or commit `SEALED`;
- response loss cannot authorize credential replay or a second submission;
- crash injection at every numbered step reaches only an allowed state;
- cleanup cannot resurrect, decrypt, or expose staged content;
- original filename, body, content, secret, and raw parser errors never enter
  application logs, audit, alerts, or tracing.

## Data inventory

| Data | Permitted handling | Prohibited handling |
|---|---|---|
| Report text | Transient strict UTF-8/NFC/LF canonicalization and encryption; durable canonical ciphertext only | Pre-normalization/raw copy, logs, audit, plaintext queues/files/DB |
| Attachment bytes | Transient reviewed pipeline; durable original ciphertext | Django default temp spool, public object, ordinary download |
| Original filename | Immediate validation only, then discard | Persistence, path use, logs, audit, UI |
| Attempt credential | One form/POST/retry context; minimal verifier/index | URL, logs, IP/device binding, cross-attempt tracking |
| Ticket ID | Approved random public identifier; bind to one accepted report | Sequential/predictable encoding |
| Recovery Secret | Transient generation and one response opportunity | Plaintext persistence, logging, URL, admin recovery, re-display |
| Report-DEK | Approved Key Service live domain only | Application logs/storage, historical restorable backups |
| Audit metadata | Allowlisted event codes and system identifiers | Reporter input, filenames, secrets, keys, raw errors |

## Recorded project-owner decision

On 2026-08-25 the project owner approved all five recommended choices:

| Decision | Approved policy |
|---|---|
| Lost credential response | Accept the residual availability loss; never reissue or replace credentials and never duplicate the same attempt |
| Attempt credential | One opaque, single-use, non-sliding credential valid for two hours before first claim; exact encoding/verifier remains in its dependent review |
| Attempt state model | Approve `READY -> PROCESSING -> CIPHERTEXT_STAGED -> AUDIT_CONFIRMED -> ACCEPTED` and the one-way `ABORTING -> ABORTED` branch |
| Audit phases | Approve receipt-gated `SUBMISSION_ACCEPTANCE_REQUESTED`, truthful final `SUBMISSION_RECEIVED`, and best-effort controlled `SUBMISSION_ACCEPTANCE_FAILED` |
| Reconciliation and cleanup | Scan at least once per minute; after 15 minutes without verified progress move to `ABORTING`; retry scoped cleanup at intervals capped at five minutes; request an administrator alert if cleanup is still incomplete 15 minutes after entering `ABORTING` |

The attempt's two-hour pre-claim validity is independent from the 15-minute
processing progress deadline. Once one POST claims the attempt, client expiry
cannot transfer ownership or authorize a second pipeline.

Even after those choices, implementation remains blocked until the dependent
CAPTCHA, recovery encoding/verifier, AEAD, Key Service, audit receipt,
aggregate-size, and applicable file/sandbox gates are approved.

## Inert Stage A implementation evidence

The metadata-only `SubmissionAttempt` initial migration is guarded by a
non-executing exact-AST policy. The policy fixes its sole numbered-file graph,
empty dependencies, imports, exact internal fields, closed state/version
constraints, and terminal timestamp pairing. It rejects added reporter data,
credentials, keys, request metadata, data/SQL/custom-code operations, dynamic
behavior, graph changes, malformed source, and out-of-root paths without
importing, executing, or echoing the target.

This evidence does not enable a form, endpoint, attempt credential, protected
transition executor, reconciler, encryption, audit call, external service,
PostgreSQL concurrency claim, or production submission capability.

The controlled transition error, closed attempt-state graph, pure monotonic
server-time planner, and metadata-only model are separately guarded by a
non-executing exact-AST policy. It makes any new state or edge, sensitive field,
caller-selected time, logging effect, weakened constraint, mutation success,
database capability, or other executable change an explicit review event.
Passing remains static source evidence and adds no protected executor or
runtime authority.

The submission-audit phase profile is represented by inert descriptors and a
non-executing exact-AST source policy. They fix only the approved
`SUBMISSION_ACCEPTANCE_REQUESTED`, `SUBMISSION_RECEIVED`, and
`SUBMISSION_ACCEPTANCE_FAILED` order, timing labels, authorization windows,
durable-receipt flags, and content-free allowed/forbidden payload-field
metadata. They do not append audit events, create or verify durable receipts,
inspect attempt state, call the Audit Collector, create report keys, persist
submission metadata, expose endpoints, or authorize acceptance.

The Phase 0-6 submission acceptance checkpoint profile is represented by inert
descriptors and a non-executing exact-AST source policy. They fix only the
approved phase order, checkpoint labels, requirement labels, and forbidden
runtime capability categories. They do not parse requests, validate
credentials, claim attempts, append audit events, verify receipts, call the Key
Service, encrypt content, write storage, commit database state, render
responses, run reconciliation, expose endpoints, or authorize acceptance.

The submission-attempt credential policy is represented by inert descriptors
and a non-executing exact-AST source policy. They fix only the approved
single-use semantics, two-hour non-sliding pre-claim lifetime, POST body and
protected same-site cookie transport labels, URL/query/referrer/header-log
denials, independence from report content, Ticket ID, Recovery Secret, IP
address, User-Agent, reporter accounts, and device fingerprints, plus minimum
verifier/index, database uniqueness, row/state-version, and no-log/no-audit
metadata. They do not generate or verify credentials, persist credential
material, install cookies, inspect requests, claim attempts, call services,
expose endpoints, authorize submission, or authorize report read.

The reconciliation profile is represented by inert descriptors and a
non-executing exact-AST source policy. They fix only the approved scan-at-least
once-per-minute maximum interval, 15-minute progress deadline, five-minute
cleanup retry cap, 15-minute persistent-cleanup-alert threshold, nonterminal
candidate states, terminal outcome labels, action registry, alert type, and
content-free payload allow/deny metadata. They do not scan report content,
decrypt plaintext, create credentials, append audit events, verify receipts,
call the Audit Collector, Key Service, or Alert Service, delete ciphertext,
mutate attempts, schedule jobs, expose endpoints, or authorize acceptance.

The duplicate/retry outcome profile is represented by inert descriptors and a
non-executing exact-AST source policy. They fix only the approved retry source
labels, required one-database-winner and no-second-pipeline outcomes,
controlled indeterminate response behavior, no credential redisplay, and
forbidden signal categories. They do not parse requests, verify attempt
credentials, claim attempts, inspect database state, create reports or
Report-DEKs, append audit events, redisplay credentials, expose status
oracles, call services, expose endpoints, or authorize acceptance.

The credential-response/lost-response policy is represented by inert
descriptors and a non-executing exact-AST source policy. They fix only the one
live post-acceptance display opportunity, controlled indeterminate retry
result, permitted Ticket ID and Recovery Secret field names for that live
response, and forbidden persistence categories for plaintext Recovery Secret,
redisplay/replacement state, `credentials_delivered` claims, content
hashing/deduplication, request headers, and raw errors. They do not generate
credentials, persist or redisplay secrets, issue replacements, record delivery,
deduplicate by content, render responses, inspect requests, mutate attempts,
expose endpoints, or authorize recovery/submission.

## External design references

- [RFC 9110, HTTP Semantics — idempotent methods and retry](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2)
- [Django 5.2 — file uploads](https://docs.djangoproject.com/en/5.2/topics/http/file-uploads/)
- [Django 5.2 — CSRF protection](https://docs.djangoproject.com/en/5.2/howto/csrf/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
