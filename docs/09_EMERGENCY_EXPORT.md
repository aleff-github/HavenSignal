# 09 — Emergency Export

## Purpose

Emergency Export is an exceptional "break-glass" mechanism for circumstances where original submitted material must be preserved outside the platform, e.g. serious threats or material potentially relevant to competent authorities.

This is deliberately the only ordinary mechanism that creates a persistent copy of original report content outside the normal report lifecycle.

## Eligibility

Any operator who currently has the report in a valid OPEN state may initiate Emergency Export.

## Required safeguards

Before generation:

1. operator selects an allowlisted system reason code and enters the mandatory protected note, maximum 1,000 characters;
2. UI warns not to insert unnecessary report content into the reason;
3. CAPTCHA is required by current business decision;
4. single-use action-bound step-up MFA/FIDO2 authorization is required for the exact ticket and `EMERGENCY_EXPORT` operation and, where available before authorization, the exact artifact/request digest;
5. `EMERGENCY_EXPORT_REQUESTED` must be durably accepted and produce the required audit receipt;
6. the administrator is notified of the export event.

The proposed exact step-up TTL, WebAuthn ceremony, and canonical export-request
binding are in `docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md`. They remain
OPEN pending the consolidated pre-code decision and independent review. The
artifact must not be released if a mandatory audit or notification precondition
has not reached its approved durable state.

## Export contents

Logical package should contain:

```text
report.txt
attachments/
  <server-generated-safe-name>.pdf
  <server-generated-safe-name>.jpg
  ...
manifest.json
```

The package preserves:

- authoritative accepted report text byte-for-byte: the strict UTF-8, LF, NFC
  representation defined by `docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`;
- accepted attachment bytes byte-for-byte;
- relevant system-generated receipt/export metadata;
- file sizes;
- cryptographic hashes of report text/files;
- audit-relevant reopening reasons where required by the current decision.

Full protected reopening/export notes may be included in the encrypted package. Permanent audit contains only the system reason code and structured metadata.

Original reporter filenames are not preserved because the system intentionally discards them.

“Original report text” does not mean the transient browser/wire byte sequence
before canonicalization. The project-owner-approved rule keeps no second raw
text copy: Emergency Export decrypts and exports exactly the canonical bytes
that were accepted and encrypted. This avoids creating an additional sensitive
representation while preserving the exact platform-accepted content.

## Manifest

Manifest should include:

- non-sensitive internal/public ticket reference as appropriate;
- submission timestamp;
- export timestamp;
- attachment list using server-generated names;
- file sizes;
- strong cryptographic hashes;
- format/version information.

Manifest should be digitally signed by the organization/instance.

Signature-key lifecycle must be separately managed.

## Encryption

The final export must not be an ordinary password-protected ZIP.

The export artifact must be encrypted to a preconfigured organization public key using an approved public-key encryption tool/format.

The organization holds the corresponding private key under a separately approved process.

The operator may download the encrypted artifact.

The exact public-key encryption format, manifest-signature construction, key identifiers/versioning, and key-rotation procedure require explicit approval before implementation.

Plaintext package components and temporary files must be minimized, isolated, and deleted through a defined normal/crash/timeout cleanup lifecycle. No unnecessary plaintext export artifact may persist.

## Audit

Audit stores:

- export event;
- operator identity;
- system-defined export reason code;
- timestamp;
- cryptographic hash of the final encrypted artifact;
- result status.

Audit does NOT store a copy of the export artifact.

Audit does not store the full arbitrary operator note.

## Lifecycle after export

Emergency Export does not convert the platform into permanent storage.

The internal report continues through the normal lifecycle.

When a Response Note is ultimately finalized, internal report content/key must still be destroyed.

## Legal posture

The system may preserve technical integrity and traceability but MUST NOT claim universal legal admissibility or evidentiary status across jurisdictions.

## Accepted residual risk

Any authenticated operator holding a legitimate current OPEN lease may deliberately invoke Emergency Export. No second operator is required.

CAPTCHA, action-bound MFA, audit receipts, encryption, signed manifests, and administrator notification provide attribution and detection. They do not mathematically prevent a legitimately authorized operator from choosing to create the encrypted persistent copy.
