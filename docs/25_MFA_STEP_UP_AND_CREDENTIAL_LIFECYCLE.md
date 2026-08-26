# 25 — MFA Step-Up and Credential Lifecycle

## Status

**OWNER-APPROVED DESIGN (2026-08-26) — independent authentication/security
review remains required. No login, enrollment, reset, recovery, step-up,
finalization, export, deletion, or administrator endpoint is authorized.**

This proposal defines the supported production WebAuthn profile, exact
step-up/artifact binding, server-side one-time authorization, credential
enrollment and replacement, lost-factor recovery, and failure behavior. It does
not approve a WebAuthn library/version, authenticator model, relying-party
domain, workstation build, service-authentication topology, or deployment.

## Governing requirements

- `SEC-AUTH-001..009`;
- `SEC-ACCESS-010..015`;
- `SEC-LOG-004..005`, `SEC-LOG-009..012`;
- `SEC-ROLE-001..004`;
- `SEC-FINALIZE-001..006`;
- `SEC-EXPORT-001..006`;
- `SEC-BROWSER-001..002`.

The trust boundaries in `docs/15` and `docs/19`, audit protocol in `docs/23`,
and exact Response Note bytes in `docs/24` remain authoritative.

## Supported production authenticator profile

Operator and Application Administrator authentication uses:

1. the account password; and
2. a WebAuthn/FIDO2 multi-factor cryptographic authenticator with user
   verification.

The supported production profile requires organization-approved,
hardware-backed, device-bound security keys. Syncable/multi-device passkeys,
platform-only credentials, TOTP, HOTP, SMS, email codes, push approval, security
questions, recovery links, and password-only fallback are not supported.

Each person enrolls two distinct approved security keys. One is the normal key;
one is a sealed backup under the organization's documented custody procedure.
Both require a locally configured activation PIN or biometric user verification.
The server never receives that activation secret or biometric sample.

WebAuthn relying-party configuration is fixed per deployment:

- one exact operator/admin RP ID under an approved HTTPS origin;
- an exact allowlist of origins; no wildcard, HTTP, dynamic Host-derived, or
  caller-selected origin;
- `userVerification = "required"` for registration and authentication;
- `residentKey = "discouraged"` because password login already identifies the
  account and discoverable credentials are unnecessary;
- attestation required at enrollment and checked against an offline, pinned,
  organization-approved authenticator/AAGUID allowlist;
- backup-eligible or backup-state flags are rejected for the device-bound
  production profile;
- allowed COSE algorithms are ES256 (`-7`) and EdDSA (`-8`) only, subject to the
  pinned authenticator/library compatibility review;
- no unknown WebAuthn extension is trusted for authorization.

The attestation trust store is updated only through a separately authenticated,
reviewed administrator procedure. Authentication never makes a reporter-facing
or runtime third-party metadata request.

## WebAuthn challenge and assertion verification

Every ceremony uses a fresh 32-byte operating-system CSPRNG challenge stored
server-side. Challenges:

- expire after 120 seconds from server time;
- are single-use and bound to one account, server session, RP ID, origin,
  ceremony type, and operation context;
- are submitted only through POST/session-bound state, never URLs;
- are never logged, placed in audit, localStorage, IndexedDB, or reusable
  browser storage.

The verifier checks the complete WebAuthn procedure, including:

- exact ceremony type and challenge;
- exact origin and RP ID hash;
- HTTPS and expected top-level/cross-origin state;
- user-presence and user-verification flags;
- credential ownership, enabled state, approved AAGUID/attestation profile, and
  allowed algorithm;
- authenticator-data/client-data structure and signature;
- token binding/channel data when the selected library/profile requires it;
- backup-eligibility/state flags;
- signature counter under serialized credential-row access.

For a device-bound credential with a nonzero stored/current signature counter,
a new counter less than or equal to the stored value fails closed, disables the
credential pending security review, and creates a controlled alert. A
counterless authenticator is allowed only if its exact approved model/profile
was accepted during enrollment; zero is not silently treated as clone proof.

Raw client data, attestation objects, credential IDs, challenges, signatures,
user handles, authenticator metadata, IP addresses, User-Agent, and untrusted
errors never enter application/audit logs.

## Login sessions

A successful password plus WebAuthn ceremony creates a new random server-side
session identifier and rotates any pre-authentication session. Operator and
administrator sessions use distinct cookie names, URL surfaces, credentials,
and deployment profiles.

The session cookie is `Secure`, `HttpOnly`, narrowly scoped, and uses the
approved `SameSite` policy. Sensitive pages are `no-store`; CSRF remains
mandatory. A WebAuthn assertion does not repair an expired, disabled, wrong-role,
or otherwise invalid account/session.

Exact password/Argon2id parameters and session idle/absolute lifetimes remain
separate review items where not already fixed. Step-up never extends the login
session or an OPEN ReportLease.

## Artifact-binding service and key

The Step-Up Authorization Service owns a dedicated 256-bit HMAC-SHA-256
artifact-binding key. It is purpose-separated from Django `SECRET_KEY`,
password/verifier keys, WebAuthn credentials, audit keys, Recovery Secret
verifier keys, DEKs, CAPTCHA keys, export keys, TLS, and service-authentication
keys.

The service receives exact artifact bytes transiently only for a permitted
operation and returns this opaque 32-byte value:

```text
step-up-artifact-binding-v1 = HMAC-SHA-256(
  active-step-up-binding-key,
  deterministic-cbor([
    version: 1,
    purpose: "STEP_UP_ARTIFACT_BINDING",
    binding-key-epoch: uint,
    operator-id: bstr .size 16,
    session-id: bstr .size 16,
    operation: controlled-tstr,
    report-id: bstr .size 16,
    response-id: bstr .size 16 / nil,
    finalization-id: bstr .size 16 / nil,
    lease-id: bstr .size 16,
    lease-generation: uint,
    report-state-version: uint,
    artifact-kind: controlled-tstr,
    artifact-byte-length: uint,
    artifact-bytes: bstr
  ])
)
```

The HMAC input is RFC 8949 deterministic CBOR with exact types/lengths and a
closed registry. A caller cannot supply raw framed bytes, key epoch, or binding
result. Comparison is constant-time.

For `FINALIZE_RESPONSE`, `artifact-bytes` are exactly the frozen canonical UTF-8
Response Note bytes from `docs/24`. For `EMERGENCY_EXPORT`, they are the exact
canonical export-request descriptor fixed by the export protocol because the
encrypted artifact does not yet exist. For deletion or account-security
operations, the applicable protocol fixes an exact canonical descriptor; free
text is never copied to audit.

Artifact bytes are not persisted by the Step-Up service. The opaque binding may
be stored in the short-lived authorization row and, where required by
`docs/23`, in audit. A plain unkeyed hash of a short Response Note or protected
operator note is prohibited because it would enable confirmation guessing.

Binding keys rotate at least every 30 days. The retired key remains available
only for ten minutes so already-issued two-minute authorizations can finish,
then is destroyed. Historical opaque audit bindings remain unverifiable as
content guesses after key destruction; audit event signatures remain valid.

## Exact server-side StepUpAuthorization

No self-contained bearer token is used. PostgreSQL stores a server-authoritative
row:

```text
StepUpAuthorization v1
  authorization_id: random 16-byte identifier, unique
  operator_id: internal 16-byte identifier
  session_id: internal 16-byte identifier
  operation: closed registry
  report_id: internal 16-byte identifier
  response_id: internal 16-byte identifier or null
  finalization_id: internal 16-byte identifier or null
  lease_id: random 16-byte identifier
  lease_generation: monotonic integer
  report_state: closed registry
  report_state_version: monotonic integer
  artifact_kind: closed registry
  artifact_binding: 32 bytes
  binding_key_epoch: integer
  webauthn_credential_row_id: internal identifier
  issued_at: server time
  expires_at: issued_at + 120 seconds
  consumed_at: server time or null
  consumed_by_operation_id: internal identifier or null
```

The browser receives only an independent random 32-byte opaque handle for the
row, encoded as unpadded Base64url and held in the rendered form/session. Its
keyed verifier/index is stored server-side. The handle is never sufficient by
possession: every use also validates authenticated operator, exact server
session, operation, current report/lease/state/version, artifact binding,
expiry, unused state, CSRF, and the operation's other controls.

The handle is POST-only, never a URL/query value, cookie with cross-operation
scope, log field, audit field, localStorage value, or downloadable object.

This version-1 row is report/lease-bound. It does not authorize a metadata-only
administrative batch operation. `docs/32_RETENTION_AND_DELETION_PROTOCOL.md`
proposes a separately reviewed administrative-batch profile for the exceptional
flood ceremony; that extension is not approved by this document and cannot be
implemented by inserting dummy report or lease identifiers into version 1.

`docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md` proposes the exact
version-2 administrative row/profile needed for non-report security operations,
plus the supported role workstations and session lifetimes. That proposal does
not amend this document until consolidated approval and independent review.

## Step-up issuance and consumption

Issuance:

1. require a current authenticated password-plus-WebAuthn session and valid
   OPEN lease where applicable;
2. canonicalize/freeze the exact artifact or operation descriptor;
3. compute the opaque artifact binding inside the Step-Up service;
4. create the operation-bound WebAuthn challenge under a database lock;
5. verify one fresh assertion with user verification required;
6. revalidate account/session/report/lease/state/version and artifact binding;
7. invalidate the challenge and issue one authorization row/opaque handle with
   a non-sliding 120-second expiry.

Consumption:

1. accept the opaque handle only in the protected POST body/session;
2. lock authorization, report, lease, and operation rows in one documented
   order;
3. revalidate every binding and current server time;
4. recompute the artifact binding from the exact bytes/descriptor;
5. validate CAPTCHA, audit receipt, notification, and other independent gates;
6. atomically mark the authorization consumed in the same PostgreSQL
   transaction that commits the protected operation's irreversible local state
   transition or operation ownership;
7. downstream services accept only the immutable operation/finalization ID,
   binding, state version, and their own authenticated/audited authorization.

A finalization authorization is consumed with the exact staged-response and
`FINALIZING` transition. An export authorization is consumed when the fenced
export workflow becomes the unique authorized owner, before any artifact
release. A failed downstream call does not unconsume or extend step-up; the
same committed workflow resumes idempotently without asking the user to
authorize different bytes.

Unknown outcome before the local consumption transaction is retried through the
same idempotency context. Once consumption may have committed, a new step-up
cannot act on the same one-time state; server state resolves the winner.

## Enrollment

Operator enrollment requires all of:

- an approved account created disabled and assigned only the Operator role;
- in-person identity verification under the organization's documented process;
- the operator and two distinct authorized officers from separate trust roles;
- two new approved hardware authenticators presented during the ceremony;
- exact origin/RP ID, user verification, attestation, algorithm, AAGUID, and
  device-bound checks;
- private PIN/biometric activation by the operator outside officer knowledge;
- a successful assertion from each credential after registration;
- controlled audit events and independent notification to the operator through
  a pre-established organizational channel;
- explicit enablement only after the ceremony is complete.

The Application Administrator may create/disable account metadata but cannot
complete operator credential enrollment, retain a registered key, select a key
under administrator custody, issue a session, set the operator activation PIN,
or impersonate the operator.

Administrator enrollment uses the same strength and two-key requirement but a
separate administrator surface/RP credential set. Operator credentials do not
authenticate to administrator endpoints and vice versa.

## Adding or replacing a still-controlled factor

An authenticated person who still controls one enrolled key cannot silently add
a new factor online. Replacement requires:

1. password and fresh assertion from an existing active key;
2. in-person presence and one authorized officer outside the person's own role;
3. a 24-hour pending period with controlled notification;
4. a second confirmation using the existing key after the pending period;
5. enrollment and post-registration assertion from the new approved key;
6. revocation of the replaced key when applicable and termination of all
   sessions/step-up authorizations.

No report may remain OPEN during factor change. Security staff can cancel a
pending change; they cannot shorten the delay through the application.

## Lost-factor recovery and reset

There is no self-service, email, SMS, help-desk-link, recovery-code, TOTP,
password-only, administrator-generated key, or emergency bypass.

If one of two keys is lost, the still-controlled-factor replacement procedure
applies and the lost credential is disabled immediately.

If all keys are unavailable:

1. disable the account and terminate sessions, leases, challenges, and step-up
   authorizations;
2. require in-person repeated identity verification;
3. require two-person approval from distinct authorized trust roles, neither of
   whom can authenticate as the recovered user;
4. enforce a non-bypassable 24-hour cooling-off period with controlled alerts;
5. enroll two new approved authenticators with the user present;
6. revoke every old credential and require a password reset through the
   separately approved high-assurance process;
7. independently review audit evidence before re-enabling the account.

Application Administrator authority alone cannot initiate and complete these
steps. Infrastructure/Key Custodian authority alone also cannot do so. Database
or deployment access is not an account-recovery mechanism.

An unavailable quorum or notification path leaves the account disabled. There
is no availability fallback, even for urgent reports.

## Failure behavior

| Failure | Required result |
|---|---|
| Wrong origin/RP/challenge/type/flags/signature | Generic denial; consume challenge where safe |
| Unapproved/syncable/unknown authenticator | Deny enrollment/authentication |
| Counter regression for nonzero device-bound counter | Deny, disable credential, controlled alert |
| Challenge or authorization expired | Deny; no renewal or sliding extension |
| Artifact/context/state/lease mismatch | Deny; no partial consumption or protected effect |
| Duplicate authorization use | One database winner; every later use denied |
| Binding-key/WebAuthn/audit/CAPTCHA dependency unavailable | Protected operation fails closed |
| Crash after authorization consumption | Resume only the same immutable workflow; never change artifact |
| Lost factor or suspicious enrollment | Disable affected credential/account and terminate sessions |
| Recovery quorum/notification unavailable | Account stays disabled; no bypass |
| Unknown account-recovery state | Fail closed and require independent review |

## Required tests before enablement

Release-blocking tests must cover:

- W3C WebAuthn positive/negative vectors and the selected library's official
  fixtures for registration and assertion verification;
- exact origin/RP ID, challenge, ceremony type, UV/UP, signature, algorithm,
  AAGUID/attestation, backup flags, credential ownership, and extension checks;
- device-bound counter serialization, regression, zero-counter approved-model
  behavior, and tightly synchronized assertion races;
- 32-byte challenge entropy, single use, 120-second expiry, and no URL/log/browser
  persistence;
- RFC 8949/HMAC-SHA-256 artifact-binding vectors, domain separation, exact-byte
  changes, cross-operator/session/operation/report/lease/version replay, and
  constant-time comparison;
- 20–100 synchronized authorization consumptions across PostgreSQL connections
  and processes produce one winner and one immutable workflow;
- crashes before/after challenge use, authorization issue, local consumption,
  audit receipt, and downstream calls reach only documented states;
- retired binding-key destruction prevents later content-guess verification
  without invalidating audit signatures;
- operator/admin RP, role, credential, cookie, session, and deployment
  separation;
- no administrator-only enrollment/reset/recovery or session impersonation path;
- two-key enrollment, lost-one replacement, lost-all recovery, 24-hour delays,
  quorum failure, notification failure, and session/lease termination;
- raw WebAuthn material, identifiers, challenges, signatures, artifact bytes,
  operator notes, and untrusted errors never enter logs/audit/alerts/traces.

Browser mocks alone are insufficient. Acceptance requires supported hardware
authenticators, pinned browsers, the hardened workstation profile, PostgreSQL
multi-process concurrency, and an isolated test RP/origin matching production
semantics.

## Consolidated decisions approved at the pre-code gate

The project owner approved the following on 2026-08-26:

1. hardware-backed device-bound WebAuthn keys, two per person, with no weaker
   fallback or syncable passkey in the supported production profile;
2. exact RP/origin/UV/attestation/AAGUID/algorithm/backup-flag profile;
3. 120-second WebAuthn challenge and 120-second non-sliding server-side
   StepUpAuthorization;
4. HMAC-SHA-256 deterministic-CBOR artifact binding and 30-day/ten-minute
   binding-key lifecycle;
5. transaction-bound single-use consumption and immutable workflow resume;
6. in-person enrollment/replacement/recovery, two-role quorum, two authenticators,
   24-hour delay, and no administrator-only or remote fallback.

Independent authentication/security review, authenticator procurement and
attestation validation, library pinning, exact RP/origin, password/session
profile, workstation build, organizational identity-proofing procedure, alert
transport, and deployment acceptance remain required after owner approval.

## External design references

- [W3C — Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [NIST SP 800-63B — Authenticator requirements](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
- [NIST SP 800-63B — Authenticator event management](https://pages.nist.gov/800-63-4/sp800-63b/events/)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)
- [RFC 8949 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html)
