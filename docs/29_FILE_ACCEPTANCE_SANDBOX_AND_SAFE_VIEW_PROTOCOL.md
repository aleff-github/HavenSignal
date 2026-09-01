# 29 — File Acceptance, Sandbox, and Safe-View Protocol

## Status

**OWNER-APPROVED DESIGN (2026-08-26) — independent parser/sandbox review
remains required. No PDF, JPEG, PNG, upload endpoint, attachment decryption,
parser, renderer, or safe-view endpoint is authorized.**

This proposal closes the version-1 structural profiles, decoded-resource
ceilings, parser families, disposable microVM boundary, transient plaintext
lifecycle, and operator safe-view format. Exact release artifacts remain a
release-time pinning gate because supported security patches change.

## Governing requirements

- `SEC-CONF-001..008`;
- `SEC-ANON-002..004`;
- `SEC-LOG-003..005`, `SEC-LOG-009..011`;
- `SEC-ACCESS-001..015`;
- `SEC-FILE-001..006`;
- `SEC-BROWSER-001..002`;
- `SEC-INPUT-002..006`.

The accepted-original-byte policy in `docs/07`, submission sequence in
`docs/20`, report-object framing in `docs/26`, and Key Service policy in
`docs/27` remain authoritative within their status and gates.

## Accept, store, process, serve

The four stages are separate security decisions:

1. **Accept:** outer request controls admit only a bounded candidate; a
   disposable sandbox independently parses and renders it under the exact
   profile below.
2. **Store:** only accepted original bytes are encrypted under the report's DEK
   using server-generated identifiers; original filenames never persist.
3. **Process:** every later original-byte decrypt goes only to one fenced,
   disposable sandbox job. Django and the Operator Console never receive it.
4. **Serve:** normal operator viewing receives only a newly rasterized PNG safe
   representation through a no-store authenticated response. Original bytes
   are never ordinarily downloaded or rendered inline.

Passing one stage never bypasses checks in another. Extension, client MIME,
magic prefix, successful decoding, antivirus result, or successful render is
never sufficient by itself.

## Common admission rules

- At most one PDF and three images; each is at most exactly 5 MiB = 5,242,880
  server-observed bytes.
- Candidate length must be at least 1 byte and agree at every proxy, multipart,
  broker, sandbox, and encryption boundary.
- Filename is transient defense-in-depth only and must match
  `^[A-Za-z]{1,64}\.(pdf|jpg|jpeg|png)$` with the lowercase extension matching
  the sandbox-classified kind. It is discarded immediately after validation.
- Client `Content-Type`, `Content-Disposition`, path, extension, metadata, and
  magic bytes are untrusted and are never storage or execution inputs.
- No archive, SVG/XML, Office, PostScript/EPS, video, audio, HTML, text, polyglot,
  or unknown format is accepted through an attachment field.
- A parser warning, repair, truncated input, trailing bytes, ambiguous format,
  parser disagreement, unsupported feature, limit uncertainty, or nonzero
  controlled tool result rejects the entire submission; there is no
  attachment-dropping or weaker fallback.

Accepted original bytes and embedded metadata are preserved byte-for-byte only
inside the approved encrypted report object and Emergency Export. The reporter
UI warns before submission that attachments may contain identifying metadata
and that the platform cannot guarantee anonymity of submitted content. The
server does not silently alter an evidentiary original.

## JPEG version-1 profile

The complete byte stream must be one ISO/IEC 10918-compatible baseline
sequential JPEG interchange stream:

- exact SOI first and EOI last, with no leading or trailing bytes;
- exactly one SOF0; 8-bit samples; one grayscale or three color components;
- exactly one SOS covering every declared component; no progressive,
  arithmetic, lossless, hierarchical, JPEG-LS, JPEG 2000, MPO, or abbreviated
  table-only stream;
- width and height each `1..4096`; decoded pixels at most `16,777,216`;
- marker count at most 512; every length and table/reference must be valid;
- APP0..APP15 and COM metadata may remain opaque but together may occupy at
  most 1 MiB; embedded thumbnails are structurally bounded but never separately
  decoded or shown;
- no second concatenated image, alternate codestream, or bytes after EOI.

The sandbox decodes the full image with a latest-patched, pinned libjpeg-turbo
3.x build under strict warning-as-error behavior. The result must agree with the
independent marker scanner on dimensions, components, and complete consumption.
Decoded working data is capped at 64 MiB.

## PNG version-1 profile

The complete byte stream must be one PNG 1.2-compatible image:

- exact eight-byte signature, IHDR first, one or more consecutive IDAT chunks,
  IEND last, and no trailing bytes;
- width and height each `1..4096`; decoded pixels at most `16,777,216`;
- compression/filter method 0 and non-interlaced method 0 only;
- valid bit-depth/color-type combinations from the PNG specification;
- every chunk CRC, length, order, and multiplicity valid; at most 1,024 chunks;
- only IHDR, PLTE, IDAT, IEND, tRNS, gAMA, cHRM, sRGB, and pHYs are accepted;
  every text, EXIF, ICC/compressed-profile, APNG, time, suggested-palette,
  unknown critical, or other ancillary chunk is rejected;
- total non-IDAT ancillary data at most 1 MiB; compressed IDAT bytes remain
  within the 5 MiB file limit; expanded scanline data at most 64 MiB and
  decompression ratio at most 100:1.

The sandbox fully decodes with a latest-patched, pinned libpng 1.6.x build.
The decoder and independent chunk scanner must agree on format, dimensions,
color model, ordering, CRCs, complete consumption, and resource totals.

## PDF version-1 structural profile

PDF input is limited to versions 1.4 through 2.0 and must satisfy all of:

- unencrypted and no password/security handler;
- exact `%PDF-` header within the first 8 bytes, valid final `%%EOF`, and no
  non-whitespace bytes after the final marker;
- qpdf exits with success and no warning, recovery, damaged-xref, or repaired
  object/page-tree condition;
- at most 20 pages, 10,000 indirect objects, 5,000 streams, object/reference
  traversal depth 64, and no dangling or cyclic structure outside semantics
  explicitly allowed by the PDF standard and accepted by both tools;
- each page box has positive finite dimensions no greater than 1,440 points per
  side; rendered dimension no greater than 4,096 pixels per side;
- embedded image XObjects each have at most 16,777,216 decoded pixels and the
  sum across unique image objects is at most 50,000,000 pixels;
- each decoded stream at most 32 MiB, total decoded stream data at most 128 MiB,
  and per-stream/aggregate decompression ratio at most 100:1;
- no annotation, AcroForm/XFA, JavaScript, action, OpenAction, additional action,
  URI/remote-go-to, launch, submit/import, embedded file/filespec, collection,
  portfolio, multimedia, RichMedia, 3D, movie, sound, optional executable
  content, external reference, or alternate rendition;
- no PostScript/XObject subtype, embedded source file, arbitrary file-system
  reference, or feature requiring network/resource retrieval;
- metadata streams may remain as encrypted original evidence but are not
  surfaced to operators or fed to an XML/general metadata parser.

Structural inspection uses pinned qpdf 12 JSON-v2 output with stream bytes
omitted and a closed semantic policy walker. Rendering uses a separately pinned
MuPDF `mutool draw` build, explicitly as PDF input, at 144 DPI. Current reference
families are qpdf 12.4 and MuPDF 1.27; the release candidate must pin supported
patched artifacts by digest and repeat review/corpus testing. ImageMagick,
Ghostscript, browser PDF viewers, Poppler utilities, and OS default applications
are not fallback paths.

qpdf and MuPDF must agree on page count, page geometry, successful full-file
consumption, and bounded render completion. All pages must render; a partial
success rejects the file. Renderer stdout/stderr is treated as untrusted and
mapped to controlled result codes, never copied into logs/audit/alerts.

## Safe-view representation

Every operator-visible attachment becomes one or more new PNG files:

- JPEG/PNG: fully decode, convert to 8-bit sRGB RGB/RGBA, strip all metadata,
  and encode one non-interlaced PNG;
- PDF: render each requested page at 144 DPI to an 8-bit sRGB RGB PNG, without
  annotations or external resources;
- each output dimension at most 4,096 pixels, each output at most 16 MiB, total
  rendered pixels per job at most 50,000,000, and total output at most 128 MiB;
- output is independently decoded/validated by the restricted PNG verifier
  before release; no original filename, embedded metadata, link, text layer,
  attachment, script, form, or vector object survives.

Admission renders and validates every page/image but discards the output. During
an authorized OPEN lease, a new one-page/one-image view job decrypts exactly one
bound original object into the sandbox and streams the validated PNG directly
to the Operator Console. Safe views are not durable report objects, blob-store
objects, cache entries, browser-persistent objects, or audit payloads.

Responses are authenticated and lease/generation/state-version bound, POST
initiated, `Cache-Control: no-store`, `Content-Type: image/png`,
`X-Content-Type-Options: nosniff`, and use a fixed server-generated disposition
name. They have a restrictive CSP, no Range/public URL, and no original-byte or
alternate content negotiation.

## Disposable microVM sandbox

Production parsing and rendering occurs in one fresh Linux Firecracker microVM
per job, using the supported latest patched Firecracker release (v1.16.1 is the
current reference at this decision date), the production `jailer`, default
seccomp filters, KVM isolation, namespaces, dropped privileges, and cgroup
limits. A normal process, Django worker, Docker container alone, or antivirus
process is not equivalent.

Each microVM has:

- 1 vCPU, 768 MiB RAM, at most 32 guest processes/threads, 128 open file
  descriptors, 60-second parser/render wall time, and 120-second absolute job
  lifetime;
- no virtual NIC, MMDS, DNS, host network namespace, package manager, shell,
  SSH, cloud credential, production credential, Key Service credential, or
  writable shared host filesystem;
- read-only measured root image containing only the broker agent and pinned
  validators/renderers; Secure Boot/measured-image handling is a deployment
  acceptance item;
- input/output only over an authenticated host/guest vsock protocol with exact
  job ID, object ID, kind, byte length, monotonic sequence, output ceiling, and
  one-time capability;
- guest RAM/tmpfs only for plaintext; swap, hibernation, microVM snapshots,
  core dumps, ptrace, crash upload, and persistent console/file logs disabled;
- a fresh boot for every job, zero reusable workspace, forced termination and
  memory release on success, rejection, timeout, disconnect, or crash.

The host broker has no parser and cannot redirect a job to arbitrary storage or
network. It accepts one exact input stream, one controlled verdict, and bounded
safe-view or accepted-original output. The microVM cannot initiate connections.
Host/jailer paths and images are root-owned, immutable to service users, and
verified by approved digest before boot.

## Submission plaintext lifecycle

1. The outer request layer counts bytes and creates one random attempt/job ID;
   no reporter filename becomes a path.
2. Each candidate is streamed once into the fresh microVM's bounded RAM/tmpfs;
   neither reverse proxy nor Django writes an upload temporary file.
3. The sandbox validates and fully renders/decodes; safe outputs are discarded.
4. On rejection, the microVM is destroyed and the submission fails as a whole.
5. On acceptance, the microVM retains the exact original only until the
   submission obtains its required audit receipt and provisional Report-DEK.
6. The broker streams the exact accepted bytes once to the job-bound Key Service
   encryption operation; the Key Service returns only the approved ciphertext
   envelope. No plaintext returns to Django.
7. Exact length/kind/object bindings are checked, then the microVM is destroyed.

The interval from final candidate byte to microVM destruction is at most 120
seconds. Failure to obtain audit/key/encryption authorization in time destroys
the job and requires a new submission. Availability never extends plaintext
retention or permits a disk spool.

## Operator-view plaintext lifecycle

The Key Service validates the exact current operator, report, OPEN/REOPEN lease,
generation, state/version, object, sandbox-job identity, and applicable
`ATTACHMENT_VIEW_REQUESTED` audit receipt before streaming one original object
to one fresh microVM. The worker returns only the validated PNG. The Operator
Console cannot select a destination, receive original bytes, invoke a general
decrypt, or reuse the job after expiry.

Every view job ends after one image/page response or 60 seconds, whichever is
earlier. Refresh/page navigation creates a new audited, lease-bound job. Failure
returns no original or partial representation and has no ordinary-download
fallback.

## Controlled records and logging

Durable metadata may contain only system-generated object ID, controlled kind
and slot, encrypted-envelope reference, fixed frame profile, accepted byte
length, controlled validator-profile version, and controlled outcome code. It
must not contain original filename, client MIME, metadata values, content hash,
dimensions/page count if unnecessary for workflow, parser output, or plaintext.

Sandbox/broker metrics use only controlled stage/result/resource-bucket codes.
Raw filenames, bytes, tool command lines containing paths, stdout/stderr,
exceptions, request headers, file hashes, and metadata never enter logs, audit,
alerts, traces, crash reports, or third-party scanning.

## Failure behavior

| Failure | Required result |
|---|---|
| Missing/oversized/extra/duplicate part | Reject whole submission before durable report material |
| Filename/MIME/magic/profile disagreement | Reject; never rename into acceptance |
| Parser warning, repair, disagreement, or uncertainty | Reject; no alternate parser fallback |
| Decode/decompression/pixel/object/page/output limit | Terminate microVM and reject |
| Sandbox unavailable or image/digest mismatch | Attachments remain disabled; no in-process fallback |
| Audit/Key Service unavailable after validation | Destroy plaintext job at deadline; no spool or unaudited encryption |
| Broker/vsock length, sequence, identity, or capability mismatch | Terminate and reject without partial output |
| Admission render succeeds only partially | Reject original file and whole submission |
| OPEN lease/receipt expires during view | Terminate job; release no further safe-view bytes |
| Safe-output revalidation fails | Release nothing; controlled security event |
| MicroVM crash/timeout | Destroy job and memory; controlled failure only |
| Cleanup/memory-isolation proof fails | Release-blocking sandbox acceptance failure |

## Required tests before enablement

- benign and adversarial JPEG/PNG/PDF corpora at every exact boundary;
- double extension, mixed case, NUL/control/path, MIME mismatch, magic-only,
  concatenated/polyglot, trailing data, truncation, and parser differential;
- JPEG progressive/arithmetic/lossless/multi-scan/component/marker/metadata and
  dimension/pixel-limit rejection;
- PNG CRC/order/chunk-count/interlace/bit-depth/color-type/APNG/text/ICC/unknown
  chunk and decompression-bomb rejection;
- PDF encryption, repair, xref/object stream, dangling/cyclic reference,
  JavaScript/action/form/annotation/embedded-file/external-reference/media,
  object/page/stream/decompression/image/render and parser-disagreement cases;
- safe output contains only the approved non-interlaced metadata-free PNG
  profile and cannot execute, link, embed, traverse, or trigger MIME sniffing;
- operator cannot retrieve original bytes, choose a path/URL, reuse a stale
  generation, redirect sandbox output, or access another report/object;
- microVM has no NIC/MMDS/swap/snapshot/core/ptrace/credential/shared-write path
  and cannot escape via parser, guest, vsock, jailer, or host-broker abuse corpus;
- crash/timeout/kill at every intake, validation, audit, encryption, view, and
  teardown boundary leaves no durable plaintext or reusable capability;
- filesystem, host cache/swap policy, logs, audit, alerts, traces, queues,
  backups, VM images, and crash handling contain no reporter file data;
- pinned qpdf, MuPDF, libjpeg-turbo, libpng, Firecracker, guest kernel/rootfs,
  and broker artifacts pass SBOM, signature/digest, CVE, fuzz/corpus, and
  reproducibility review on every upgrade.

## Consolidated decisions approved at the pre-code gate

1. exact JPEG, PNG, and PDF version-1 structural/resource profiles above;
2. qpdf JSON-v2 semantic inspection plus full MuPDF rasterization for PDF;
3. libjpeg-turbo/libpng full decode with independent structural scanners;
4. 4,096-pixel/16,777,216-pixel image and 20-page/10,000-object PDF ceilings;
5. metadata-preserving encrypted originals but metadata-free PNG-only safe view;
6. one fresh Firecracker microVM per admission/view job with the stated limits;
7. no proxy/Django/plaintext disk spool, microVM snapshot, ordinary download,
   or parser fallback;
8. job-bound streaming from sandbox to encryption and from Key Service through
   sandbox to the current operator lease.

Independent parser/sandbox review, exact patched artifact pinning, production
KVM host/jailer/kernel/root-image/broker review, fuzz corpus, Key Service/audit
integration, PostgreSQL concurrency, and deployment validation remain release
gates after owner approval.

## Inert Stage A implementation evidence

The current `security_interfaces/attachment_admission_descriptors.py` module
models only content-free common attachment-admission metadata: slot counts,
file-size bounds, accepted kind/slot/extension registries, transient
defense-in-depth filename shape, and the explicit denial that client MIME,
Content-Disposition, paths, extensions, magic bytes, parser warnings, or partial
success are authoritative.

It does not inspect file bytes, parse JPEG/PNG/PDF, create sandbox jobs, persist
originals, retain original filenames, log request material, expose upload or
safe-view endpoints, encrypt attachments, or authorize uploads.

A non-executing exact-AST policy locks this descriptor source profile and
rejects file-byte inspection, parser behavior, sandbox-job creation,
original-byte persistence, filename persistence, request-material logging,
upload authorization, dynamic, logging, file, network, Django-integration, and
service-call changes without importing or executing the target. Passing is
source-conformance evidence only and closes no parser, renderer, sandbox,
encryption, safe-view, endpoint, deployment, or production gate.

The current `security_interfaces/safe_view_descriptors.py` module models only
content-free safe-view metadata: PNG-only output, 8-bit sRGB profile, 144 DPI
PDF-rendering metadata, output dimensions and byte limits, no-store/nosniff
response headers, POST initiation, required operator/state/lease/object
bindings, non-durable safe-view handling, and ordinary original-download denial.

It does not decrypt attachment bytes, render files, validate PNG bytes, call a
sandbox, persist safe output, serve responses, inspect leases, or authorize
operator access.

A non-executing exact-AST policy locks this descriptor source profile and
rejects decrypt, render, PNG-validation, sandbox-call, persistence,
response-serving, endpoint, dynamic, logging, file, network,
Django-integration, service-call, and authorization changes without importing
or executing the target. Passing is source-conformance evidence only and closes
no decrypt, renderer, restricted-PNG verifier, sandbox, lease, response,
endpoint, deployment, or production gate.

The current `security_interfaces/file_sandbox_descriptors.py` module models
only content-free sandbox-boundary metadata: Firecracker reference, one fresh
microVM per job, vCPU/RAM/process/file-descriptor/time limits, authenticated
vsock transport, read-only measured root, guest RAM/tmpfs-only workspace,
one-time job capability, no production credentials, and explicit denial of
network, shell, SSH, ptrace, swap, snapshots, core dumps, reusable storage
credentials, and shared writable host storage.

It does not boot microVMs, execute parsers, open files, create jobs, exchange
vsock messages, inspect attachments, persist plaintext, log request material,
or authorize file processing.

A non-executing exact-AST policy locks this descriptor source profile and
rejects microVM boot, parser execution, file access, job creation, vsock
exchange, attachment inspection, plaintext persistence, endpoint, dynamic,
logging, file, network, Django-integration, service-call, and authorization
changes without importing or executing the target. Passing is source-conformance
evidence only and closes no Firecracker, jailer, kernel/rootfs, broker, vsock,
parser, renderer, sandbox-execution, deployment, or production gate.

## External design references

- [qpdf 12 JSON representation](https://qpdf.readthedocs.io/en/latest/json.html)
- [qpdf structural checking](https://qpdf.readthedocs.io/en/stable/cli.html#option-check)
- [MuPDF `mutool draw`](https://mupdf.readthedocs.io/en/1.27.0/tools/mutool-draw.html)
- [PNG 1.2 chunk specification](https://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html)
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Firecracker seccomp](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md)
