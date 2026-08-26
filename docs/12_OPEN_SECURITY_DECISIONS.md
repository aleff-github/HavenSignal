# 12 — Open Security Decisions

Do not silently resolve these in code. An OPEN item blocks only the affected security component unless this document explicitly says otherwise.

## CRITICAL — Recovery credential encoding and verifier

The approved model is a random public Ticket ID plus an independent 256-bit Recovery Secret, with no short PIN.

Still OPEN:

- Recovery Secret generation location and the no-JavaScript-compatible generation/delivery flow;
- exact Ticket ID bit length and encoding;
- exact Recovery Secret encoding;
- exact copy/display behavior beyond the server-side display-once rule;
- exact keyed verifier construction, framing, domain separation, key lifecycle, and rotation.

The failure behavior when a report is durably accepted but the one-time
credential response does not reach the reporter is approved in
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`: accept the residual availability
loss, never reissue or replace credentials, and never duplicate the same
attempt.

`docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md` contains the owner-approved exact
encoding, HMAC-SHA-256 verifier, key-separation, rotation, and failure policy.
Its five owner choices were approved on 2026-08-25. This gate remains OPEN for
implementation until the independent cryptographic review is complete.
Lost-response sequencing is governed separately by approved
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`.

## CRITICAL — Response Note cryptographic construction

The approved model uses an independent Response-DEK. The Recovery Secret is not the sole material sufficient to decrypt a retained/restored ciphertext indefinitely.

Still OPEN:

- exact AEAD construction;
- nonce strategy;
- AAD and format/version binding;
- key derivation and purpose separation;
- exact verifier construction;
- Response-DEK wrapping/unwrapping construction;
- Response-DEK representation and lifecycle protocol.

`docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md` defines the owner-approved
version-1 construction: libsodium XChaCha20-Poly1305-IETF, constant-length
canonical plaintext framing, deterministic-CBOR AAD/envelope, a non-exportable
Key Service Response-DEK, inert provisional staging, and server/Key-Service
enforced first-read expiry. Owner approval was recorded on 2026-08-25, but the
construction is not yet implementation-authorizing.

Independent cryptographic/protocol review, step-up artifact binding, Key Service
product/topology/HSM and non-resurrection proof, service authentication,
trusted clocks, PostgreSQL concurrency/durability, audit implementation, and
deployment remain separate blockers.

## CRITICAL — Original report cryptographic construction

`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md` proposes the exact random
non-exportable Report-DEK, RFC 5869 HKDF-SHA-256 object-subkeys,
XChaCha20-Poly1305, fixed-length frames, deterministic-CBOR context, staging,
and narrow-use model. It also proposes defining `5 MB` as exactly 5 MiB.

The six listed choices await consolidated pre-code owner approval and
independent cryptographic review. Key Service, file/sandbox, storage,
concurrency, audit, and deployment gates remain independently blocking.

The project owner approved one contained choice on 2026-08-25: report text is
normalized to LF and NFC, encoded as strict UTF-8, and that accepted canonical
representation is the sole authoritative original. No separate raw
pre-normalization copy is retained. This resolves the earlier export wording
conflict but does not approve the other `docs/26` choices or close its review
and implementation gates.

## CRITICAL — Emergency Export cryptographic construction and workflow

`docs/28_EMERGENCY_EXPORT_CRYPTOGRAPHIC_PROTOCOL.md` proposes binary
single-recipient X25519 `age` v1 encryption, a closed uncompressed `ustar`
profile, RFC 8785 manifest bytes, detached COSE Sign1/Ed25519, exact request
binding, distinct-role recipient-key activation, fenced streaming generation,
encrypted-only staging, and one-shot delivery.

Its eight listed choices await consolidated pre-code owner approval and
independent cryptographic/protocol review. Alert transport/durable acceptance,
Key Service/export capability, pinned tools, signer/HSM, external private-key
custody, PostgreSQL concurrency, audit deployment, workstation handling, and
production isolation remain independently blocking.

## CRITICAL — Key Service product, topology, and proof of non-resurrection

The policy is approved:

- live replication of active Report-DEKs and Response-DEKs is permitted;
- restorable historical per-object DEK backups/snapshots are forbidden;
- catastrophic loss of active reports is accepted rather than risking key resurrection.

Still OPEN:

- final Key Service product;
- exact topology and replication configuration;
- exact Key Service capability/policy implementation;
- exact Infrastructure / Key Custodian operational procedure.

OpenBao remains only a candidate. Approval requires a release-blocking proof of concept covering delete propagation, snapshot/restore, rollback, delayed/stale replicas, and disaster recovery.

`docs/27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md` proposes the exact
candidate-neutral capability matrix, workload authentication, forward-only key
states, backup prohibition, destructive test environment, and binary verdict.
It explicitly permits rejection of OpenBao and cannot itself substitute for the
real PoC. Its six choices await consolidated pre-code owner approval;
product/topology approval remains OPEN until every test passes independently.

`docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md` separately proposes
the exact custodian staffing/access/quorum/break-glass procedure. It does not
select or approve a product/topology and must be exercised by the real PoC.

## CRITICAL — Audit receipt and tamper-evidence construction

The approved lifecycle requires pre-action durable receipts and
REQUESTED/AUTHORIZED/COMPLETED/FAILED events where needed.

`docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` defines the exact
owner-approved version-1 construction. Owner approval was recorded on
2026-08-25, but the construction is not yet implementation-authorizing.

Approved choices:

- deterministic CBOR, COSE Sign1/Ed25519, separated receipt/checkpoint keys,
  and the exact event/receipt schemas;
- idempotency/nonces and per-operation non-sliding receipt lifetimes;
- RFC 9162 Merkle and RFC 9942 proof profiles plus the 60-second/1,024-event
  merge rule;
- five-minute heartbeats, seven-minute witness alerting, and fail-closed
  cessation of protected receipt issuance within 90 seconds;
- key rotation and 365-day event / 730-day verification-evidence retention.

Independent cryptographic/protocol review remains mandatory. Audit topology,
HSM/signer, service authentication, PostgreSQL
durability/concurrency, clock, alert transport, deployment, and dependent-flow
reviews also remain OPEN.

Hash chaining alone is not acceptable. The proposal instead uses independently
witnessed signed Merkle checkpoints to detect mutation, gaps, forks,
truncation, rollback, and cessation.

## CLOSED — Submission acceptance, audit, and credential-delivery sequencing

The failure-safe sequence between:

- durable audit acceptance;
- report encryption/key creation;
- metadata/ciphertext persistence;
- one-time Ticket ID/Recovery Secret delivery;
- retry after connection loss;

was approved by the project owner on 2026-08-25. The design must not accept an
unaudited report silently, leak plaintext, duplicate a submission through
unsafe retry, or claim that credentials were delivered when the one-time
response was lost.

`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` is the approved authority for the
sequence, state model, audit phases, retry behavior, reconciliation timing, and
lost-response residual risk. The dependent CAPTCHA, recovery
encoding/verifier, report crypto, Key Service, audit receipt, aggregate-size, and
applicable file/sandbox gates remain independently blocking.

## CRITICAL — Emergency Export cryptographic formats

The organization public-key encryption and signed-manifest properties are approved.

Still OPEN:

- exact public-key encryption tool/format;
- exact manifest-signature construction;
- key identifiers and artifact format versioning;
- organization public-key rotation/revocation procedure;
- export-signing key lifecycle.

## HIGH — No-JavaScript anti-bot technology

The no-JavaScript path must be self-hosted, server-side, single-use, briefly expiring, use global abuse controls, and avoid IP/device fingerprinting and third-party tracking.

The project-owned no-JavaScript protocol and exact five-minute expiry are
owner-approved. ALTCHA remains only the JavaScript-enabled candidate.

`docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md` defines the owner-approved five-minute,
single-attempt, purpose/scope-bound protocol and global anonymous token buckets.
It rejects direct use of the reviewed `django-simple-captcha` validator because
its database consumption is not explicitly concurrency-atomic. This gate
remains OPEN for implementation until pinned Pillow/font, self-hosted
audio/accessibility, PostgreSQL concurrency, and production-boundary reviews
are complete.

## HIGH — PDF structural acceptance profile and sandbox

`docs/29_FILE_ACCEPTANCE_SANDBOX_AND_SAFE_VIEW_PROTOCOL.md` proposes the exact
page/object/decompression/dimension ceilings, structural deny/allow profile,
qpdf/MuPDF pipeline, PNG raster view, Firecracker microVM boundary, and
temporary plaintext lifecycle.

No accepted PDF may be described as absolutely safe.

## HIGH — Image resource limits and sandbox

The same `docs/29` proposal defines decoded pixel/dimension limits,
libjpeg-turbo/libpng plus independent scanners, metadata-free PNG re-encoding,
and exact shared microVM limits.

The eight consolidated file/sandbox choices await owner approval and
independent review. Exact supported artifact pinning, fuzz corpus, production
KVM/jailer/kernel/root-image/broker, Key Service/audit integration, concurrency,
and deployment remain independently blocking.

## HIGH — MFA step-up and credential lifecycle

The action-bound `StepUpAuthorization` properties are approved.

`docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md` proposes:

- a 120-second WebAuthn challenge and non-sliding server-side authorization;
- deterministic-CBOR HMAC-SHA-256 artifact binding with a separately held key;
- device-bound hardware WebAuthn keys, two per person, and no weaker fallback;
- in-person enrollment/replacement/recovery with separate-role quorum and a
  24-hour delay;
- explicit administrator anti-impersonation and operator/admin RP separation.

These choices await consolidated pre-code owner approval and independent
authentication/security review. Authenticator procurement/attestation,
library pinning, exact RP/origin, workstation, identity-proofing, alert, and
deployment procedures remain OPEN.

## HIGH — Operator workstation hardening specification

`docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md` proposes Ubuntu
Desktop 26.04 LTS, Firefox ESR 153, signed/drift-controlled images, Secure Boot,
passphrase LUKS2, no swap/hibernate/local admin, an ephemeral one-origin kiosk,
no clipboard/print/capture/cloud/ordinary download, restricted networking, and
an encrypted-only Emergency Export transfer broker.

Its exact choices await owner and independent endpoint/authentication/network
review, hardware/tool validation, artifact pinning, kiosk/broker implementation,
physical procedure, and production acceptance.

## HIGH — Never-read Response Note retention

`docs/32_RETENTION_AND_DELETION_PROTOCOL.md` proposes a 90-day deadline from
`response_available_at` only while no first read has won. A valid first read
before the boundary receives the full existing 72-hour window. Owner and
legal/operational approval, independent review, exact Key Service transition,
trusted clocks, concurrency proof, and deployment remain OPEN.

## HIGH — SEALED report deletion during floods

`docs/32` proposes closed admission plus infrastructure capacity attestation,
Application Administrator declaration, two Operator approvals, a 30-minute and
100-report cap, deterministic newest-first SEALED-only selection inside a fixed
flood interval, no human content view/AI/scoring, per-report audit receipts,
and skip-on-race behavior. Its exact choices await owner and independent
security/operations review.

## HIGH — Operator deletion without Response Note

`docs/32` proposes OPEN-only eligibility, the `SPAM`, `EMPTY`, and
`UNMANAGEABLE_CONTENT` registry, an optional encrypted 150-character note,
CAPTCHA, exact-descriptor step-up, a forward-only `DELETING` workflow, durable
pre-destruction audit receipt, generic recovery behavior, and explicit race
handling. These choices await consolidated owner approval and independent
review.

## HIGH — Aggregate request and decoded-resource limits

`docs/26` and `docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md` propose
defining each `5 MB` as exactly 5 MiB, the complete submission body as 21 MiB,
the sum of file bodies as 20 MiB, and the exact multipart/time/memory ceilings.
`docs/29` proposes the remaining decoded-resource limits.

The eight request/multipart decisions await consolidated owner approval and
independent HTTP/proxy/Django review. Exact reverse-proxy configuration, custom
upload-handler review, request-smuggling/desynchronization testing, no-spool
production evidence, and dependent challenge/file/crypto gates remain blocking.

## MEDIUM — Administrator alert transport

`docs/31_ADMINISTRATOR_ALERT_PROTOCOL.md` proposes a separately deployed
self-hosted Alert Service, durable administrator inbox, organization-operated
SMTP wake-up queue, a closed content-free schema, synchronous durable
acceptance, idempotent retry, acknowledgement/escalation, 365-day retention,
and an exact per-operation failure matrix.

Its six choices await consolidated owner approval and independent
security/operations review. Service authentication, PostgreSQL durability and
concurrency, SMTP/mailbox deployment, administrator access hardening,
retention-job isolation, monitoring, and staffing/runbooks remain blocking.

## HIGH — Audit retention expiry authority

Audit retention is 365 days, while the report application has no historical
delete authority. `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` defines
collector-controlled 365-day event retention and 730-day verification-evidence
retention. The durations are owner-approved; the expiry implementation and
proof that application/operator roles cannot accelerate deletion remain OPEN.

`docs/32` proposes the daily isolated retention job, dependency checks,
controlled batch evidence, distinct-role configuration change, and fail-safe
retain-longer behavior. Exact implementation and production proof remain OPEN.

## HIGH — Administrator network/session access profile

`docs/33` proposes a physically separate administrator workstation, distinct
VPN/device certificate/RP/origin/cookie/account/factor set, ten-minute idle and
four-hour absolute session, no report route or operator impersonation, and a
separate 120-second administrative exact-artifact step-up profile. Owner,
independent review, exact infrastructure, and production proof remain OPEN.

## MEDIUM — Infrastructure / Key Custodian operational procedure

`docs/33` proposes at least three individually named custodians, two-person
sensitive ceremonies, separate hardened workstations/network, a self-hosted
bastion, hardware-backed OpenSSH certificates valid at most 15 minutes,
allowlisted command wrappers, vendor/HSM dual-control break-glass, quarterly
restore and annual full exercises, and no report/per-object-key authority.
Owner/operations review, staffing, infrastructure products, HSM/CA, exact
runbooks, and production-equivalent tests remain OPEN.
