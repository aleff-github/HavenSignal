# 06 — Operator Access and Sessions

## Supported workstation profile

The security baseline assumes a dedicated, hardened operator workstation.

The application may technically run on ordinary workstations, but the project MUST NOT claim equivalent protection outside the supported hardened profile.

## Authentication

Operator login requires:

- password;
- strong second factor;
- WebAuthn/FIDO2 preferred.

Password storage should use Argon2id with settings reviewed against current OWASP guidance.

## One active report per operator

An operator may not hold multiple active reports simultaneously.

Purpose:

- reduce forgotten open reports;
- reduce accidental cross-report handling;
- simplify accountability;
- narrow plaintext exposure.

## Claim

CLAIM is the action.

CLAIMED is the resulting state.

The operator must CLAIM before seeing any report content.

CLAIMED lasts at most 5 minutes without OPEN.

## Open lease

OPEN is a server-authoritative processing lease.

Each OPEN period has a persisted `ReportLease` containing at least:

- report identifier;
- operator identifier;
- random lease identifier;
- monotonically increasing generation/fencing token;
- `opened_at`;
- `last_activity_at`;
- `absolute_expires_at`;
- state/version.

Timeouts:

- idle: 5 minutes;
- absolute: 60 minutes.

Timeout enforcement occurs server-side.

Only server-side time is authoritative. Every sensitive OPEN action validates the operator, `lease_id`, current generation, report state, idle expiry, and absolute expiry.

Refreshing the page during a still-valid OPEN lease does not create a reopening.

A new lease generation invalidates stale tabs, previous sessions, late retries, and delayed requests from all earlier generations.

## Interruption / reopening

After lease loss or interruption, the report requires reopening.

Reopening requires:

- an authenticated operator;
- an allowlisted system reason code;
- an optional arbitrary operator note where required by the flow;
- maximum 150 characters;
- warning not to include report content;
- encrypted operational-history storage for the note;
- permanent audit of the system reason code and structured outcome only.

The arbitrary note is destroyed with the ticket and is not copied into permanent audit. It may be included in Emergency Export.

No supervisor approval is required in the baseline.

No maximum number of reopenings is defined.

The reopening operator may differ from the previous operator.

## Concurrency

The backend must guarantee:

- one active report per operator;
- one active operator lease per report;
- no concurrent final responses;
- no race between finalization and export;
- no stale session reactivation after finalization.

Use database transactions/locking and explicit state-version checks as appropriate.

Use database uniqueness constraints sufficient to enforce one active report per operator and one active lease per report.

Do not rely only on frontend disabled buttons.

## Final response

The operator composes the Response Note only in the active session.

No persistent server-side draft.

Immediately before irreversible final publication:

- step-up MFA is required;
- CAPTCHA is additionally required by current business decision;
- the system must verify audit availability;
- the step-up authorization must be single-use and bound to the operator, ticket, `FINALIZE_RESPONSE`, nonce, expiry, and digest of the exact Response Note bytes;
- finalization must enter `FINALIZING` and follow the approved idempotent, resumable multi-service protocol.

After finalization, the original report cannot be reopened.

Once the committed `FINALIZING` transition occurs, ordinary operator rendering/editing, reopen, and Emergency Export are disabled for that report; only the scoped finalization resume path remains valid.

`docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md` contains the proposed exact
120-second step-up, WebAuthn profile, HMAC artifact binding, enrollment,
replacement, and recovery procedures. It remains non-authorizing pending the
consolidated pre-code owner decision, independent authentication/security
review, hardware/library validation, workstation profile, and deployment gates.
