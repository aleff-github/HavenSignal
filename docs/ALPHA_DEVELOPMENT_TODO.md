# HavenSignal Alpha Development Checklist

This checklist tracks the remaining work required for a locally testable
HavenSignal alpha. It is a delivery checklist, not an authorization to handle
real disclosures. Security-sensitive capabilities remain disabled until their
listed evidence and review gates are satisfied.

## Alpha outcome

The alpha is complete when a contributor can use the Docker environment and
synthetic data to exercise this entire flow:

1. submit one text disclosure;
2. receive a Ticket ID and Recovery Secret exactly once;
3. authenticate as an authorized operator;
4. claim and open the encrypted disclosure under a fenced lease;
5. create exactly one plain-text Response Note;
6. destroy the original report key after durable finalization evidence;
7. retrieve only the Response Note with the recovery credential.

Attachments may remain disabled in the first text-only vertical slice, but the
alpha is not complete until the reviewed attachment and safe-view path is also
available for synthetic testing.

## Phase 1 — Complete metadata-only Stage A

Target: 7–20 September 2026.

- [x] Add PostgreSQL metadata constraints and monotonic transition planners.
- [x] Prove nine metadata contention scenarios with 20 processes each.
- [x] Implement fenced preparation, activation, and prepared abort metadata.
- [x] Rehydrate exact `PREPARED` metadata after database reconnection.
- [x] Prove transaction rollback after result-construction failures.
- [ ] Prove committed preparation survives application process termination and
      rehydration by a separate process.
- [ ] Prove an interrupted uncommitted preparation leaves no partial operation.
- [ ] Exercise committed-state recovery after a controlled PostgreSQL container
      restart without treating it as failover or backup/restore evidence.
- [ ] Add regression coverage for malformed persisted operation state and
      version/timestamp combinations.
- [ ] Record a binary Stage A exit result while keeping claim, open, content,
      service calls, and protected execution disabled.

Exit condition: the present metadata boundary has process-level and local
database-restart evidence, and every test remains fail-closed outside real
PostgreSQL.

## Phase 2 — Security-service proofs and review inputs

Target: 21 September–18 October 2026. External review can extend this phase.

- [ ] Build deterministic CBOR and COSE interoperability test vectors for the
      approved Audit v1 protocol.
- [ ] Implement a local Audit Service proof of concept with durable pre-action
      receipts, idempotency, signed checkpoints, and witness-failure tests.
- [ ] Prove the application cannot complete a protected action without the
      required durable audit receipt.
- [ ] Select a Key Service candidate for the destructive acceptance harness.
- [ ] Run delete propagation, stale replica, snapshot, restore, rollback, and
      disaster-recovery non-resurrection tests.
- [ ] Reject the candidate if any deleted per-object key can be resurrected.
- [ ] Add exact report and Response Note cryptographic interoperability vectors
      without exposing a public submission path.
- [ ] Obtain and record independent cryptographic/protocol review outcomes.
- [ ] Resolve only those implementation changes required by review findings.

Exit condition: Audit and Key Service proofs pass, the exact cryptographic
profiles interoperate, and mandatory independent review blockers are closed.

## Phase 3 — Text-only encrypted submission

Target: 19 October–15 November 2026.

- [ ] Implement the bounded no-JavaScript challenge with atomic single-use
      consumption and anonymous global abuse controls.
- [ ] Implement the reviewed request admission boundary and streaming text-only
      upload path with no disk spooling.
- [ ] Normalize and frame report text using the approved UTF-8, NFC, and LF
      profile.
- [ ] Create the Report-DEK through the accepted Key Service capability.
- [ ] Encrypt and persist the fixed-frame report ciphertext and minimal metadata.
- [ ] Append and verify every required submission audit event and receipt.
- [ ] Generate the Ticket ID and Recovery Secret and persist only the keyed
      verifier representation.
- [ ] Display the recovery credential exactly once and never claim delivery
      after a lost response.
- [ ] Implement idempotent retry and reconciliation for every approved failure
      boundary.
- [ ] Keep attachment inputs explicitly disabled during this slice.

Exit condition: a synthetic text submission completes end to end in Docker,
while dependency failures remain generic, content-free, and fail-closed.

## Phase 4 — Operator access and one-response finalization

Target: 16 November–13 December 2026.

- [ ] Implement separate operator authentication and hardware-backed WebAuthn
      enrollment/test profiles.
- [ ] Enforce server-side session, workstation, origin, and step-up boundaries.
- [ ] Implement atomic claim and opening transitions with one active report per
      operator and one fenced lease per report.
- [ ] Decrypt report text only through the narrowly scoped Key Service action.
- [ ] Prevent plaintext persistence, ordinary downloads, clipboard-oriented
      responses, and reporter-controlled logging.
- [ ] Validate and encrypt exactly one Response Note.
- [ ] Execute receipt-gated finalization and Report-DEK destruction.
- [ ] Prove replay, stale lease, stale step-up, process interruption, and service
      failure cannot produce duplicate responses or unauthorized state changes.

Exit condition: an authorized synthetic operator can produce one response and
the original report becomes cryptographically unavailable after finalization.

## Phase 5 — Reporter recovery

Target: 30 November–20 December 2026; this may overlap non-blocking Phase 4
work but cannot bypass its security dependencies.

- [ ] Implement constant-time Recovery Verifier Service verification with a
      generic external result.
- [ ] Enforce CAPTCHA, audit receipt, eligibility, and Key Service authorization
      before Response Note decryption.
- [ ] Implement atomic first-read selection and the fixed 72-hour read window.
- [ ] Implement the 90-day never-read expiry path without extending either
      deadline through retries.
- [ ] Render only the fixed-frame plain-text Response Note with no-store headers,
      no active links, and no reply path.
- [ ] Destroy the Response-DEK at the approved expiry boundary and prove recovery
      becomes permanently unavailable.

Exit condition: a reporter with the valid credential retrieves only the one
Response Note, and all invalid or expired cases remain indistinguishable.

## Phase 6 — Attachments and operational workflows

Target: 14 December 2026–17 January 2027.

- [ ] Pin and verify the approved image, PDF, rasterization, and sandbox
      artifacts.
- [ ] Implement streaming attachment admission with exact count, type, and size
      bounds.
- [ ] Run hostile-file handling inside the reviewed isolated microVM boundary.
- [ ] Produce metadata-free bounded PNG safe views with no original-file
      download path.
- [ ] Add fuzz, decompression-bomb, parser-crash, timeout, and cleanup tests.
- [ ] Implement retention, deletion, reconciliation, and retry workers with
      fenced idempotent operations.
- [ ] Implement durable administrator alerts without report or credential data.
- [ ] Exercise operator deletion, flood deletion, and Emergency Export only
      after their independent gates are satisfied.

Exit condition: synthetic allowed attachments can be reviewed only through safe
views, and every cleanup or administrative workflow has durable failure recovery.

## Phase 7 — Alpha stabilization and release

Target: 18 January–14 February 2027. External assessment findings can extend
the target.

- [ ] Run the complete Docker flow from a clean clone using documented local
      secrets and PostgreSQL storage.
- [ ] Add browser-to-database end-to-end tests for submission, operator
      finalization, and recovery.
- [ ] Run concurrency, process-kill, database-restart, disk-full, clock, network,
      and dependency-failure campaigns.
- [ ] Complete accessibility and no-JavaScript testing.
- [ ] Prove backup/restore procedures cannot resurrect destroyed per-object keys.
- [ ] Complete an independent security assessment and resolve release-blocking
      findings.
- [ ] Confirm that logs, metrics, traces, alerts, and fixtures contain no reporter
      content, credentials, plaintext, or stable reporter identifiers.
- [ ] Publish contributor test instructions, supported limitations, upgrade and
      rollback procedures, and residual risks.
- [ ] Tag the first reproducible `v0.1.0-alpha` release only after every alpha
      exit condition is satisfied.

## Rules for every implementation item

- [ ] Add or update tests before enabling a success path.
- [ ] Keep mandatory dependency failures fail-closed; never add a weaker fallback.
- [ ] Use only synthetic data until the controlled-pilot gate is separately met.
- [ ] Update requirements traceability and status documentation in the same
      change as the implementation evidence.
- [ ] Make one English commit per coherent novelty.
- [ ] Push the exact validated commit to `alpha-direct`, wait for native,
      PostgreSQL, and CodeQL success, then promote the same commit to `main`.
- [ ] Do not use pull requests before the alpha is complete, as directed by the
      project owner.
