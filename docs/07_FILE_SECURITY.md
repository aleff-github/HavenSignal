# 07 — File Upload and Safe Viewing

## Allowed files

Baseline:

- one PDF, maximum 5 MB;
- up to three images, each maximum 5 MB;
- image formats: JPEG and PNG only.

`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md` proposes interpreting each
`5 MB` limit as exactly 5 MiB (5,242,880 server-observed bytes) and encrypting
each accepted attachment in one fixed-length frame. That choice awaits the
consolidated pre-code decision; it does not approve any file format or parser.

No DOCX, ZIP, archives, video, audio, SVG, office formats, scripts, or executable content.

## Filename input policy

The reporter-submitted basename must contain ASCII letters only.

Allowed examples:

- `Document.pdf`
- `Photo.jpg`

Disallowed examples include names containing:

- digits;
- spaces;
- punctuation;
- slashes;
- backslashes;
- path segments;
- shell metacharacters;
- control characters.

The extension must match an allowed type.

This filename rule is defense-in-depth only and is not sufficient validation.

## Original filename

The original filename:

- must never be persisted after validation/acceptance;
- must never be logged;
- must never be included in audit events;
- must never be used as a storage path;
- must never be returned to operators.

After acceptance, assign a server-generated random internal filename/identifier, e.g. UUIDv4 or equivalent safe random identifier.

The server-generated identifier is not user-controlled.

## Original bytes

For an accepted file, the original file bytes and embedded metadata are preserved as received.

The platform does not automatically strip EXIF/PDF metadata because metadata may be evidentiary.

Reporter-facing guidance may explain how the reporter can remove metadata before submission using external/local tools if they choose.

## Validation

Do not trust:

- extension;
- Content-Type;
- MIME value declared by browser;
- filename;
- magic bytes alone.

Validation should combine multiple signals and parser-aware checks.

## Structural acceptance profile

Any attachment that contains or appears capable of containing active/dynamic behavior not permitted by the baseline must be rejected.

For PDF, reject at minimum prohibited constructs such as:

- JavaScript;
- launch actions;
- embedded files;
- active forms/actions where unsafe;
- multimedia/active content;
- suspicious parser features outside the approved structural profile.

Uncertain or out-of-profile content must fail closed.

The system MUST NOT describe an accepted attachment as absolutely "safe." The correct claim is:

> admitted by the approved structural profile and processed only in the defined sandbox/CDR pipeline.

Even a structurally static PDF can exploit a parser vulnerability.

PDF upload remains blocked until explicit approval of:

- maximum pages;
- maximum objects;
- maximum decompression ratio;
- maximum dimensions/resource limits;
- parser/toolchain;
- structural allowlist;
- render strategy.

No values may be invented merely to remove this blocker.

Image upload/processing likewise remains blocked until decoded pixel/dimension limits, decoder/toolchain, viewing transformation policy, and sandbox/resource limits are approved.

## Sandbox

File parsing and transformation must occur in a separate, tightly sandboxed worker/process boundary.

Do not parse untrusted files in the main Django web process.

The sandbox should have:

- no unnecessary network access;
- minimal filesystem access;
- strict CPU/memory/time limits;
- no production credentials;
- no report-key authority beyond the minimum needed for the specific operation;
- disposable working directories.

The complete pipeline must define plaintext input handling, temporary workspace creation, access, timeout/crash cleanup, lease expiry, and deletion. Reporter-controlled names must never be used for temporary or durable paths.

## CDR / safe representation

Follow OWASP guidance for sandboxing and Content Disarm & Reconstruction where appropriate.

The operator should not directly open the original PDF/image using the OS default application.

Required viewing model:

1. keep original accepted bytes encrypted;
2. process in isolated worker;
3. create a temporary safe viewing representation;
4. deliver only that controlled representation to the operator;
5. delete temporary representation after the session/lifecycle requires.

For a PDF, page rendering to a non-active representation is a candidate approach, subject to parser/sandbox review.

## Ordinary download

Normal operator download of original attachments is forbidden.

The only deliberate persistent extraction path is Emergency Export.

## UI extraction controls

Defense-in-depth controls should disable ordinary:

- download actions;
- print actions;
- copy/paste of report text where feasible.

These controls do not prevent screen photography and must not be represented as absolute DRM.

## External scanning

Do not upload report files to public third-party scanning services such as VirusTotal.

Any malware/CDR scanning must be self-hosted and local to the trusted deployment boundary.
