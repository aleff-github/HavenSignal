# 32 — Retention and Deletion Protocol

## Status

**OWNER-APPROVED DESIGN (2026-08-26) — legal/operational and independent
security/protocol review remain required. No unread-response expiry, operator
deletion, flood deletion, or retention-expiry implementation is authorized.**

This proposal defines maximum never-read Response Note retention, operator
deletion without a Response Note, exceptional SEALED deletion during a declared
capacity flood, ciphertext cleanup, terminal-metadata minimization, and audit
retention authority. It does not approve a Key Service product, audit/alert
deployment, legal retention policy, service authentication, PostgreSQL/blob
topology, or production ceremony.

## Governing requirements

- `SEC-CONF-001..008`;
- `SEC-LOG-004..012`;
- `SEC-ACCESS-010..015`;
- `SEC-AUTH-002..009`;
- `SEC-DEL-001..006`;
- `SEC-KEY-001..007`;
- `SEC-RECOVERY-003..005`;
- `SEC-RESPONSE-002..008`;
- `SEC-FINALIZE-001..006`;
- `SEC-ALERT-001..003`;
- `SEC-ROLE-001..004`.

The state model in `docs/03`, recovery construction in `docs/21`, audit
protocol in `docs/23`, Response Note protocol in `docs/24`, MFA proposal in
`docs/25`, report crypto proposal in `docs/26`, Key Service acceptance plan in
`docs/27`, and alert proposal in `docs/31` remain authoritative. Where this
proposal intentionally changes the currently open unread-retention rule or
extends an event registry, implementation remains stopped until the project
owner approves the consolidated change.

## Security outcome

Version 1 must ensure:

1. age alone never silently deletes an unprocessed SEALED or INTERRUPTED report;
2. a never-read Response Note does not remain decryptable indefinitely;
3. deletion without a response is an explicit, attributable, single-report
   operator action from a current OPEN lease;
4. flood deletion is metadata-only, exceptional, multi-person, bounded, and
   never based on report content, AI, scoring, or accusation counts;
5. a durable pre-action audit receipt precedes every DEK destruction;
6. destruction is forward-only and non-resurrectable across every supported
   replica/restore;
7. physical ciphertext deletion is retried and alerted without recreating or
   retaining a key;
8. terminal application metadata is minimized while audit evidence remains
   independently verifiable.

Cryptographic destruction is the confidentiality boundary. Physical
ciphertext deletion remains mandatory defense in depth but cannot be used as a
substitute for DEK destruction.

## Retention table

| Data/state | Version-1 rule | Expiry authority |
|---|---|---|
| Accepted `SEALED` report | No age-only automatic expiry; delayed at 7 days and urgent at 30 days | Human processing or approved exceptional deletion only |
| `CLAIMED` | Five-minute claim expiry returns to `SEALED` | State Authority server time |
| `OPEN` | Five-minute idle and 60-minute absolute lease limits | State Authority server time |
| `INTERRUPTED` | No age-only automatic deletion; remains queued for explicit reopen | Approved operator workflow only |
| Never-read Response Note | Eligible until 90 days after `response_available_at`; then deny and destroy | State Authority plus Key Service hard deadline |
| Read Response Note | Exactly 72 hours after first valid recovery authorization | Existing `docs/24` protocol |
| Original/response ciphertext after DEK destruction | Delete immediately; retry until confirmed | Scoped cleanup coordinator |
| Terminal application metadata | Until cleanup is confirmed, then 30 days | Separate metadata-retention job |
| Audit event/receipt/proof material | 365 days | Audit-retention identity only |
| Checkpoints/consistency/public-key/witness evidence | 730 days | Audit-retention identity only |
| Emergency Export outside platform | Outside platform lifecycle | Organization's separately approved external policy |

The 90-day rule applies only while `first_read_at` remains null. A valid first
read completed before that deadline receives the full existing non-sliding
72-hour read window, even when it ends after day 90. This preserves
`SEC-RESPONSE-004`; it does not cap an already-started read window early.

## Never-read Response Note expiry

When finalization publishes `RESPONSE_AVAILABLE`, the State Authority stores
one immutable:

```text
unread_expires_at = response_available_at + 90 * 24 hours
```

Both timestamps use trusted server time. The Key Service records the same hard
unread deadline as part of Response-DEK activation. The deadline is not
caller-selected, sliding, or renewable.

The Key Service adds one narrow transition:

- `CONVERT_UNREAD_TO_READ_EXPIRY` — before the unread deadline, accept exactly
  one State-Authority-committed `first_read_at` and convert the key's hard limit
  to exactly `first_read_at + 72 hours`.

This is not a general extension endpoint. It is allowed once, only from
`ACTIVE_UNREAD`, for the exact response/state/version and a first-read time
strictly before `unread_expires_at`. It cannot choose another duration, move an
existing read expiry, return key bytes, or reverse destruction.

The first-read race is:

1. obtain `RESPONSE_RETRIEVAL_REQUESTED` receipt and validate recovery as in
   `docs/24`;
2. lock the response row using State-Authority server time;
3. if time is at or after `unread_expires_at`, expiry wins and retrieval is
   denied generically;
4. otherwise commit the one immutable `first_read_at`, 72-hour expiry, state
   version, and `READ_WINDOW_ARMING` ownership;
5. request the one Key Service conversion using that exact committed context;
6. only after conversion succeeds may the existing `DECRYPT_RESPONSE` flow
   return plaintext.

A crash after step 4 starts the 72-hour window but does not expose plaintext or
extend time. The same workflow resumes idempotently. If the conversion cannot
be proven before the Key Service's unread deadline, use remains denied and the
workflow resolves forward to destruction; it never changes the first-read time
or invents a later authorization.

At the unread deadline, if no committed first read won:

1. Recovery Gateway and Key Service deny use immediately;
2. a fenced expiry workflow obtains the required durable deletion receipt;
3. Key Service destroys the Response-DEK across every supported live replica;
4. recovery verifier/state is invalidated;
5. truthful destruction/expiry outcome is audited;
6. physical ciphertext deletion starts and follows the cleanup policy.

External recovery behavior remains the same generic non-success used for an
unknown, invalid, not-ready, read-expired, never-read-expired, or deleted
ticket. No page reveals which condition occurred.

Adoption requires a closed `docs/23` event profile for response-expiry
REQUESTED/COMPLETED/FAILED phases and an exact short-lived authorization for the
destruction call. That profile carries only internal identifiers, state/version,
nonce, and controlled outcome; it never carries Ticket ID or recovery data.

## Operator deletion without a Response Note

Only the authenticated Operator currently holding the one valid `OPEN` lease
may initiate this action. `SEALED`, `CLAIMED`, `INTERRUPTED`, `FINALIZING`,
`RESPONSE_AVAILABLE`, terminal, stale-version, and expired-lease states are
ineligible.

The closed reason registry is:

- `SPAM`;
- `EMPTY`;
- `UNMANAGEABLE_CONTENT`.

The operator may add one optional protected note of at most 150 Unicode scalar
values after LF/NFC normalization. It is encrypted as ticket operational
history, excluded from permanent audit/alerts, and destroyed with the Report-DEK.
The UI warns not to include report content or identifying details.

The exact frozen descriptor bound by `docs/25` is deterministic CBOR:

```text
operator-delete-descriptor-v1 = [
  version: 1,
  purpose: "DELETE_WITHOUT_RESPONSE",
  deletion-id: bstr .size 16,
  report-id: bstr .size 16,
  operator-id: bstr .size 16,
  session-id: bstr .size 16,
  lease-id: bstr .size 16,
  lease-generation: uint,
  report-state-version: uint,
  reason-code: "SPAM" / "EMPTY" / "UNMANAGEABLE_CONTENT",
  protected-note-utf8: bstr .size (0..600) / nil
]
```

The descriptor exists transiently inside the operator/Step-Up boundary. The
Step-Up service binds its exact bytes and returns the opaque keyed artifact
binding from `docs/25`; only that binding and the separately encrypted note are
persisted. The descriptor/note bytes and any plaintext digest never enter
permanent audit. The descriptor, note, reason, lease, and state are frozen
before CAPTCHA and WebAuthn step-up.

The forward-only sequence is:

1. validate authenticated operator, CSRF, current OPEN lease/generation/state,
   reason, protected note profile, and CAPTCHA;
2. issue and verify one exact-descriptor step-up authorization;
3. append `DELETE_REPORT_REQUESTED` and obtain its context-bound durable receipt;
4. lock report/lease/deletion/step-up rows in the documented order and revalidate
   every field and server time;
5. in one PostgreSQL transaction consume step-up, create the immutable deletion
   workflow, fence the report, increment state version, and enter `DELETING`;
6. invalidate ordinary OPEN/reopen/finalization/export capabilities;
7. ask the Key Service to enter `DESTROYING` and destroy the exact Report-DEK
   using current state, version, operation, nonce, and receipt;
8. durably append `REPORT_KEY_DESTROYED` and the truthful
   `DELETE_REPORT_COMPLETED` or controlled forward-recovery outcome;
9. invalidate/remove recovery verifier and reporter-visible eligibility;
10. enter `DELETED_WITH_REASON` and start physical ciphertext/metadata cleanup.

No Response Note or Response-DEK is created. Once `DELETING` commits, the
report never returns to OPEN and the operator cannot change the reason/note.
An uncertain Key Service destruction result denies all further use and resumes
only the same deletion; it never recreates a Report-DEK.

If the original 60-second audit authorization expires before confirmed Key
Service destruction, the coordinator obtains a fresh receipt under a reviewed
`DELETE_REPORT_REQUESTED` resume profile bound to the same immutable
`deletion-id`, current `DELETING` state/version, and new nonce. It cannot change
the report, reason, note binding, selection, or workflow owner. This exact
resume profile is part of the required `docs/23` registry review.

## Exceptional SEALED deletion during a capacity flood

This procedure is unavailable during ordinary load and never activates
automatically. Before declaration, new submission admission must already have
failed closed to stop further accepted growth. Availability pressure alone is
not enough: the Infrastructure / Key Custodian must attest through a controlled
metadata-only interface that remaining encrypted-storage capacity threatens
the confidentiality/integrity boundaries or safe recovery of the service.

One ceremony requires all of:

1. Infrastructure / Key Custodian capacity attestation without report access;
2. Application Administrator declaration using strong MFA and step-up;
3. two distinct currently enabled Operators, each with password/WebAuthn and a
   fresh action-bound step-up, neither holding an active report;
4. a fixed flood interval, fixed maximum count, and immutable batch descriptor;
5. durable batch audit acceptance followed by one receipt-gated destruction
   operation per still-eligible report;
6. a maximum of 100 reports per ceremony and a non-sliding 30-minute ceremony
   expiry.

The report-bound `StepUpAuthorization` schema in `docs/25` cannot be reused
unchanged because this metadata-only batch has no report lease. Adoption
therefore requires a reviewed administrative-batch step-up profile that retains
the same password/WebAuthn strength, 120-second challenge, single use,
server-side row, keyed deterministic-CBOR artifact binding, actor/session/
operation/expiry binding, and no bearer token, but binds `batch-id` and the
exact batch descriptor instead of report/lease fields. It grants no report read
or Key Service capability. Until that profile is owner-approved and
independently reviewed, the flood ceremony remains unavailable.

The system selects candidates without exposing or processing content:

- state must still be exactly `SEALED` with no claim, lease, export,
  finalization, or deletion fence;
- `received_at` must fall inside the declared flood interval;
- selection is newest accepted first by server `received_at`, with internal
  random report ID as the deterministic tie-breaker;
- the batch view shown to humans contains only batch ID, interval, count,
  aggregate encrypted bytes, selection-rule version, and opaque artifact
  binding—not Ticket IDs, filenames, report text, attachment types, submitter
  metadata, scores, labels, or individual report IDs.

There is no AI, spam model, guided classification, accusation counting,
cross-report matching, content keyword, attachment inspection, reporter
fingerprint, IP reputation, or operator preview. The newest-first rule is a
declared capacity policy, not a claim that selected reports are malicious. The
ceremony explicitly warns that legitimate disclosures may be destroyed.

Accepted residual risk: an attacker may time a flood so that a legitimate
report also falls inside the declared interval. The controls make selection
content-blind, bounded, attributable, and reviewable; they cannot prove that
every selected report is malicious or prevent loss of every legitimate report.

The batch descriptor is frozen from system-generated metadata and receives one
opaque artifact binding under that reviewed step-up profile. Adoption requires
version-controlled audit
profiles for `FLOOD_DELETION_DECLARED`, `FLOOD_DELETION_AUTHORIZED`,
`FLOOD_DELETION_COMPLETED`, and `FLOOD_DELETION_FAILED`; those additions are a
reviewed `docs/23` registry change, not an unreviewed runtime event.

After the quorum commits, the Security Workflow Coordinator processes each
candidate separately. It locks current state, skips any report that is no
longer SEALED, obtains that report's `DELETE_REPORT_REQUESTED` durable receipt,
enters a fenced `DELETING_FLOOD` state, and destroys only that Report-DEK. A
partial batch is represented truthfully; one failure neither marks other
reports deleted nor authorizes selection outside the frozen list.

An expired per-report destruction receipt is refreshed only for the same
immutable batch/item/deletion binding and current `DELETING_FLOOD` state under
the reviewed resume profile. It does not require or permit replacement
candidates or altered approvals.

Final state is `DELETED_UNOPENED_EMERGENCY`. Recovery credentials become only
the generic non-success path. No operator note or Response Note is created.
Every surviving/failed item is reconciled forward under its own operation ID.
Repeated capacity deletion requires a completely new ceremony and cannot reuse
the previous approvals.

## Physical ciphertext cleanup

Cleanup begins immediately after durable DEK destruction. It uses exact
system-generated object identifiers from immutable encrypted-object metadata;
never filenames, prefixes derived from user input, broad globs, or caller paths.

Before the first destructive object-store/database call for an exact cleanup
job, the coordinator appends `CONTENT_DELETE_STARTED` and obtains a durable
receipt. Adoption requires a reviewed `docs/23` profile giving that event a
five-minute non-sliding authorization bound to cleanup ID, object ID, current
terminal state/version, idempotency ID, and nonce. After expiry, a retry obtains
a fresh receipt only for the same immutable cleanup scope; it cannot broaden an
object list or change the terminal state.

The retry schedule after a failed deletion attempt is approximately 5 seconds,
30 seconds, 2 minutes, then every 5 minutes for the first hour, hourly through
24 hours, and every six hours thereafter without a maximum retry count. Jitter
of at most 10 percent is system-generated. A reconciler also scans for stalled
jobs at least once per minute.

At 15 minutes after the first failed attempt, exactly one
`CIPHERTEXT_DELETE_PERSISTENT_FAILURE` alert is submitted under `docs/31`.
Alert unavailability never recreates a key and never stops the scheduled retry.
Audit unavailability prevents the next physical destructive call until its
required receipt is obtained, while the already-destroyed key remains destroyed
and reconciliation continues. Failures use closed object/stage/result codes and
no storage-provider raw error, path, filename, content, or untrusted metadata.

Deletion covers live PostgreSQL ciphertext rows, encrypted blob objects,
staged safe representations, encrypted operational history, and temporary
encrypted export staging owned by that workflow. Historical ciphertext backups
may age out under the storage policy, but remain harmless only because the
non-resurrection proof establishes that no usable DEK can return.

## Terminal application metadata minimization

Until cleanup completes, the State Authority keeps only the minimum typed
workflow/tombstone metadata needed to fence stale retries, prove object scope,
and finish cleanup. It contains no report text, filenames, protected note,
Recovery Secret, verifier, DEK material, or content-derived low-entropy digest.

Thirty days after cleanup is durably confirmed, a separately credentialed
metadata-retention job removes public Ticket ID lookup state and remaining
non-audit application metadata. Generic recovery behavior is unchanged. The
Key Service retains the minimum forward-only destroyed-key tombstone required
by the approved non-resurrection topology; normal application roles cannot
delete or reverse it.

If cleanup is incomplete or retention time is uncertain, metadata is retained
longer. No administrator, operator, application service, restored database, or
client timestamp can shorten the 30-day period or erase an active cleanup
scope.

## Audit retention expiry authority

The `docs/23` durations remain exact: event/receipt/proof material for 365 days
and signed checkpoints, consistency evidence, public-key manifests, and witness
outcomes for 730 days from collector time.

Only the isolated audit-retention identity may expire eligible rows. A daily
job computes cutoffs from trusted Audit-Collector time, refuses deletion when a
checkpoint/proof dependency is still needed, commits a controlled retention
batch record, and exposes verification evidence to the witness. The report
application, operator, Application Administrator, audit reader, collector
append caller, signer, and witness cannot request early expiry or alter the
policy clock.

A retention-policy/configuration change requires distinct-role approval,
administrator step-up, durable `SECURITY_CONFIGURATION_CHANGED` receipt, and a
new deployment version. It may extend retention but cannot shorten the
owner-approved 365/730-day minima without a new project-owner/legal/security
decision.

## Concurrency and precedence

Database locks, uniqueness, operation fences, and state versions enforce one
winner among:

- claim/open/reopen versus operator or flood deletion;
- finalization versus deletion;
- Emergency Export versus deletion;
- first read versus unread expiry;
- read expiry versus concurrent retrieval;
- duplicate deletion POSTs, workers, reconciler runs, and stale retries.

`FINALIZING`, `RESPONSE_AVAILABLE`, `DESTROYING`, `DELETING`,
`DELETING_FLOOD`, and terminal states reject new claim/open/export. A claim that
commits before the flood worker locks a SEALED candidate causes that candidate
to be skipped; the flood workflow never revokes a legitimate winning claim.
Once DEK destruction may have begun, every ambiguity resolves toward denied use
and forward completion, never reopening.

Browser state, task queues, caches, worker ownership, pre-check queries, and
SQLite are never authoritative.

## Persisted and prohibited data

| Data | Permitted persistence | Prohibited use/persistence |
|---|---|---|
| Deletion descriptor | Typed immutable operation row | URL, arbitrary fields, content, caller mutation |
| Protected deletion note | Encrypted ticket history until Report-DEK destruction | Permanent audit/alert/log/terminal metadata |
| Flood batch list | State Authority metadata until batch reconciliation and terminal retention | Human content view, scoring/classification, public Ticket IDs |
| Recovery verifier/state | Only while response/report remains eligible | Restoration after terminal destruction |
| DEK destruction tombstone | Approved forward-only Key Service domain | Application delete/reverse/recreate authority |
| Cleanup object list | Exact internal object IDs and closed states | User path, filename, broad prefix/glob |
| Audit evidence | `docs/23` store/durations | Application/admin early deletion |

No deletion, retention, cleanup, alert, audit, log, metric, trace, or exception
may contain report/response text, attachment content/metadata, original
filename, Recovery Secret/tag, DEK/key material, reporter network metadata,
arbitrary note, request body, untrusted header, or raw provider/parser error.

## Failure behavior

| Failure | Required result |
|---|---|
| CAPTCHA/step-up/audit/state/lease failure before operator deletion | No state transition or destruction |
| Crash after committed `DELETING`/`DELETING_FLOOD` | No reopening; resume only the immutable deletion workflow |
| Key Service unavailable before destruction | Keep content inaccessible under deletion fence; retry exact operation |
| Destruction outcome unknown | Deny all use and resolve forward; never recreate key |
| Audit outcome unavailable after destruction | Never falsify completion or restore key; retry truthful event |
| Ciphertext cleanup failure | Key remains destroyed; retry and alert at 15 minutes |
| Alert unavailable | Continue destructive cleanup; persist closed intent and retry alert |
| Cleanup audit receipt unavailable/expired | Keep key destroyed and ciphertext inaccessible; retry receipt, then the same scoped delete |
| Unread expiry/first-read race | One server-authoritative winner; no expiry extension beyond exact chosen rule |
| Flood quorum/attestation/audit unavailable or expired | No batch authorization or deletion |
| Candidate changed from SEALED | Skip it; never force transition or replace it with another candidate |
| Partial flood batch | Record exact per-item outcomes; no implicit batch success |
| Retention dependency/time uncertainty | Retain longer; never expire early |
| Restored stale metadata/ciphertext | Key Service remains destroyed/expired and denies use |

## Required tests before enablement

Release-blocking tests must prove:

- 20–100 synchronized first-read/90-day-expiry attempts produce one allowed
  transition and never expose plaintext after the winning deadline;
- conversion from unread to read expiry occurs once, uses the exact committed
  first-read time and 72-hour duration, and has no general extension path;
- operator deletion accepts only current OPEN lease/generation/state, exact
  reason/note/descriptor, CAPTCHA, step-up, and durable receipt;
- stale tabs, duplicate POSTs, state/version changes, finalization/export races,
  and worker crashes cannot change a frozen deletion or reopen content;
- Key Service destruction propagates and every supported snapshot, rollback,
  delayed replica, stale node, backup restore, and disaster-recovery path keeps
  the DEK unusable;
- flood deletion remains impossible until admission is closed and every
  attestation/quorum/step-up/audit/time gate succeeds;
- candidate generation is byte-for-byte deterministic, SEALED-only,
  newest-first, capped at 100, content-blind, and human views contain no
  individual ticket/report details;
- claim versus flood deletion yields one winner and changed candidates are
  skipped without substitution;
- per-item receipts precede each destruction and partial batches never claim
  all-item success;
- physical deletion retries indefinitely, alerts once at 15 minutes, and never
  uses user-controlled paths or raw provider errors;
- no physical delete occurs before the exact `CONTENT_DELETE_STARTED` receipt,
  and a refreshed receipt cannot broaden immutable cleanup scope;
- 30-day metadata and 365/730-day audit retention cannot be accelerated by any
  application/operator/administrator/restored credential;
- every prohibited-data sentinel is absent from deletion state, batch metadata,
  Key Service calls, cleanup jobs, logs, audit, alerts, metrics, traces, and
  exceptions.

SQLite, one-process tests, mock key destruction, soft-delete flags, ordinary
application backups, or a single successful object-store delete is
insufficient for release acceptance.

## Consolidated decisions approved at the pre-code gate

### Inert Stage A implementation record

The metadata-only Stage A represents the exact never-read/read-window time
rules in `report_lifecycle/retention.py`. The pure planner accepts only internal
UUID, `RESPONSE_AVAILABLE`, state-version, and trusted-timestamp metadata. It
requires an exact 90-times-24-hour unread deadline, never proposes a first read,
recognizes an already stored first-read time only strictly before that boundary
with the full exact 72-hour window, and treats equality at either deadline as
expired.

Plans are immutable and have false recovery, persistence, decryption, and
destruction capability flags. The executor is deliberately unavailable. This
record is not the PostgreSQL first-read winner, expiry workflow, recovery
authorization, audit event/receipt, Key Service call, verifier invalidation,
ciphertext cleanup, endpoint, or production evidence; every named gate below
remains in force.

The following Stage A source-policy slice statically fixes the exact retention
imports, module members, snapshot/plan fields, calls, false flags, and
always-unavailable executor without importing or executing the module. It also
rejects binding shadowing and database, key, I/O, or logging calls. This adds
review evidence only and closes none of the retained gates.

The next inert Stage A slice represents the cleanup schedule as immutable timing
metadata only. It fixes the three initial delays, one-hour and 24-hour tier
boundaries, indefinite six-hour tier, 10% jitter ceiling, one-minute reconciler
ceiling, and 15-minute alert boundary. It does not choose jitter, schedule a
retry, submit an alert, select an object, obtain a receipt, persist state, or
perform deletion; its executor is unavailable. Consequently it is not evidence
for storage, audit, alert, concurrency, worker, cleanup, or production behavior.

The subsequent non-executing source-policy slice fixes the exact cleanup target,
imports, timing members, closed enums, immutable snapshot/plan fields, false
capability flags, allowed calls/raises, protected binding names, and unavailable
executor. It rejects storage, scheduler, audit, alert, logging, path/object,
mutation, and executable behavior without importing or running `cleanup.py`.
Passing is static source evidence only and closes none of the cleanup gates.

The terminal-metadata Stage A slice represents only the minimum retention edge.
Its immutable snapshot contains internal retention/cleanup UUIDs and an optional
trusted cleanup-confirmation timestamp. Without durable cleanup confirmation it
retains metadata indefinitely and exposes no removal time. With confirmation it
computes exactly 30 times 24 elapsed hours in UTC; equality marks only that a
separately credentialed removal review is due.

The returned plan has false removal, Ticket-ID-lookup deletion, persistence,
scheduling, and external-service capability flags, and its executor is always
unavailable. It contains no public Ticket ID, Recovery Secret, verifier,
protected content, filename, path, key, or provider error. This slice does not
implement cleanup confirmation, database mutation, the retention job, generic
recovery behavior, audit expiry, or Key Service tombstone handling. The
legal/operational, independent-review, service, concurrency, and production
gates remain OPEN.

The following non-executing source-policy slice fixes the terminal-metadata
planner's exact target/import/member profile, closed disposition enum, immutable
snapshot and plan fields, five false capability flags, allowed call/raise set,
protected bindings, and always-unavailable executor. It parses but never imports
or executes `metadata_retention.py`.

Database deletion, scheduling, audit/key-service calls, I/O, logging, mutation,
dynamic syntax, public Ticket ID/recovery/path/content fields, and any executable
executor fail closed. Passing is static review evidence only: it does not prove
durable cleanup confirmation, implement the separately credentialed retention
job, alter generic recovery behavior, or authorize metadata removal. Every
dependent gate remains OPEN.

The audit-retention Stage A slice represents only the exact minimum timing and
dependency decision. Its immutable snapshot contains internal retention/
evidence UUIDs, one closed evidence class, a trusted collector timestamp, and a
strict flag for evidence still required to verify retained material. It fixes
365 times 24 elapsed hours for event/receipt/proof material and 730 times 24
elapsed hours for checkpoint/consistency/public-key-manifest/witness evidence.

Before the minimum, or after it while a verification dependency remains, the
classification retains. Otherwise equality marks only that an isolated expiry
review is due. The plan authorizes no expiry, deletes no evidence, persists no
retention batch, exposes no witness evidence, and calls no service; its executor
is unavailable. No credential, job, dependency graph, database mutation,
controlled retention evidence, witness integration, legal policy, or Audit
Service is implemented. Every dependent gate remains OPEN.

The subsequent non-executing source-policy slice fixes the audit-retention
target, imports, timing/type members, both closed enums, immutable snapshot/plan
fields, five false capability flags, allowed calls/raises, protected bindings,
and always-unavailable executor. It rejects database expiry, scheduler, witness,
network, I/O, logging, mutation, receipt/content/key fields, and executable
behavior without importing or running `audit_retention.py`.

Passing is static source evidence only. It does not prove trusted collector
time, isolated credentials, dependency correctness, persistence, retention-batch
evidence, witness integration, legal policy, or Audit Service behavior, and
closes no dependent gate.

The project owner approved the following on 2026-08-26:

1. 90-day never-read Response Note expiry, with a valid pre-deadline first read
   receiving the full existing 72-hour window;
2. OPEN-only operator deletion with the three reason codes, optional protected
   150-character note, CAPTCHA, exact-artifact step-up, and receipt-gated
   forward destruction;
3. the exceptional flood ceremony: closed admission, infrastructure capacity
   attestation, Application Administrator declaration, two Operator approvals,
   30-minute/100-report cap, and no content access;
4. deterministic SEALED-only newest-first selection inside the declared flood
   interval, with no AI/scoring/classification and skip-on-race behavior;
5. the exact ciphertext cleanup retry/alert policy and 30-day terminal metadata
   retention;
6. isolated audit-retention authority and the existing 365/730-day minima.

Legal/operational retention approval, independent security/protocol review,
`docs/23` event-registry update, Key Service product/topology and destructive
PoC, PostgreSQL concurrency/durability, blob cleanup behavior, MFA, audit,
alert, service authentication, trusted clocks, staffing, and production
ceremony remain release gates after owner approval.

## External design references

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)
- [NIST SP 800-88 Rev. 2 — Guidelines for Media Sanitization](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
