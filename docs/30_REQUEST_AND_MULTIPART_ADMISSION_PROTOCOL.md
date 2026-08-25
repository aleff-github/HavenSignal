# 30 — Request and Multipart Admission Protocol

## Status

**PROPOSED — consolidated project-owner and independent HTTP/proxy/Django
review required. No reporter submission endpoint or attachment upload is
authorized by this document.**

This proposal fixes the version-1 aggregate body ceiling, multipart grammar,
streaming behavior, time/resource limits, Django upload-handler boundary, and
failure semantics. It does not approve a reverse-proxy product/configuration,
production topology, or the still-gated attachment/challenge/crypto services.

## Governing requirements

- `SEC-ANON-001..004`;
- `SEC-CONF-001`, `SEC-CONF-008`;
- `SEC-LOG-003..005`;
- `SEC-CAPTCHA-001..004`;
- `SEC-FILE-001..006`;
- `SEC-INPUT-001..006`.

The sequencing in `docs/20`, challenge protocol in `docs/22`, fixed attachment
limit/framing in `docs/26`, and sandbox protocol in `docs/29` remain
authoritative within their stated status and gates.

## Exact version-1 limits

For the anonymous submission POST:

| Item | Exact ceiling |
|---|---:|
| Complete encoded HTTP request body | 22,020,096 bytes (21 MiB) |
| Accepted file part | 5,242,880 bytes (5 MiB) |
| Sum of all file-part bodies | 20,971,520 bytes (20 MiB) |
| Canonical report text | 5,000 Unicode scalar values / 20,000 UTF-8 bytes |
| Multipart parts | 12 |
| File parts | 4: one PDF and three ordered images |
| Non-file/control-field value | 4,096 bytes unless a stricter protocol applies |
| Sum of non-file/control-field bodies excluding report text | 32,768 bytes |
| Per-part header section | 4,096 bytes |
| Sum of multipart header sections | 32,768 bytes |
| Header fields per part | 4 |
| Multipart boundary | 16..70 printable ASCII characters |
| Streaming chunk retained by web process | 65,536 bytes |
| Total in-flight plaintext buffered by web process per request | 262,144 bytes |
| Request-header completion | 10 seconds |
| Idle gap while reading body | 15 seconds |
| Absolute body admission | 300 seconds |

The 21 MiB body ceiling deliberately leaves 1 MiB beyond the maximum four file
bodies for canonical report text, CAPTCHA/CSRF/attempt fields, MIME framing, and
headers. It is not permission to exceed any constituent limit.

All counts use raw octets received after TLS but before multipart decoding.
Proxy, Reporter Gateway, Django adapter, sandbox broker, and tests use the same
integer constants; decimal MB, client declarations, filesystem allocation, and
post-decompression sizes are not substitutes.

## Outer HTTP admission

The fixed submission URL accepts only `POST` with exactly one
`Content-Type: multipart/form-data; boundary=...` and exactly one valid decimal
`Content-Length` in `1..22,020,096`. It rejects:

- absent, duplicate, signed, nondecimal, overflowed, mismatched, or conflicting
  length;
- HTTP/1 transfer coding/chunked framing, `Content-Encoding`, `Expect`, nested
  multipart, trailer fields, request-body compression, or protocol downgrade;
- duplicate/conflicting `Content-Type`, malformed/quoted boundary, obs-fold,
  bare CR/LF, NUL/control bytes, or ambiguous front-end/back-end framing;
- unsupported method/version or any path/query variant carrying a secret.

For HTTP/2, the edge enforces the same declared length and exact DATA-octet
count, rejects connection-specific headers, and does not translate an ambiguous
request downstream. Every supported ingress/proxy/application combination must
pass request-smuggling/desynchronization differential tests before release.

The earliest network boundary stops reading and closes/rejects once any byte,
time, framing, concurrency, or rate ceiling fails. Reporter-facing access logs
still omit IP address, User-Agent, request body, query, cookie, referrer,
filename, and raw header values. Only controlled outcome and coarse resource
bucket codes may be counted.

## Closed multipart grammar

- CRLF is required for multipart delimiter/header syntax; bare LF/CR rejects.
- The final boundary is mandatory; epilogue and nonempty preamble reject.
- Each semantic field name appears at most once. Unknown, duplicate, empty-name,
  reordered-file-slot, or nested parts reject the whole request.
- Control fields and report text precede file parts; file order is PDF, then
  image slots 1..3, omitting absent slots without renumbering later slots.
- Control parts have exactly `Content-Disposition: form-data; name="..."` and
  no filename. File parts additionally have one quoted ASCII `filename` and one
  client `Content-Type`; both remain untrusted.
- `filename*`, path separators, drive/UNC syntax, percent-decoded alternates,
  RFC 2047, charset parameters, `Content-Transfer-Encoding`, extra part headers,
  duplicate parameters, escapes outside the closed ASCII grammar, and control
  characters reject.
- A part body is raw bytes. There is no base64, quoted-printable, charset
  guessing, newline conversion, or browser-MIME trust.

Exact control-field names and their tighter lengths come from their owning
approved protocols (CSRF, submission attempt, challenge identifier/answer).
The endpoint schema must be closed before implementation; the 12-part ceiling
does not authorize arbitrary fields.

## Streaming and Django boundary

The production reverse proxy streams request bytes without request-body disk
buffering. Temporary request-body files, access/body capture, WAF body archives,
APM payload capture, CDN upload storage, and retry spools are disabled. Proxy
failure must not retry a partially sent POST to another upstream.

Django's `TemporaryFileUploadHandler` and `MemoryFileUploadHandler` are removed
from this endpoint. A single reviewed `SandboxStreamingUploadHandler` is
installed before any multipart parse and:

1. counts the complete encoded body and each part independently;
2. retains at most the stated bounded chunks/control text in process memory;
3. sends each file only to one attempt/slot-bound sandbox admission job from
   `docs/29`, never to a path, temporary file, model, cache, or queue;
4. returns only an opaque, non-readable candidate/result handle to endpoint
   code; it cannot expose `.read()`, bytes, filename, or a filesystem path;
5. aborts the parser, sandbox job, and whole request on every mismatch/failure.

The adapter must preserve Django `CsrfViewMiddleware` validation of the exact
server-rendered token and host-only CSRF cookie. A production-equivalent PoC
must prove that CSRF validation, challenge consumption, and attempt ownership
work with this handler without invoking a default upload spool or reading file
content into Django. Private Django multipart interfaces are not assumed stable;
framework upgrades repeat this proof.

The request is not accepted merely because all bytes arrived. It continues only
through the approved attempt ownership, sandbox, audit, key, ciphertext,
`SEALED`, and one-time credential-response sequence in `docs/20`.

## Time, concurrency, and abuse behavior

Header/body deadlines use monotonic server time and are non-sliding. The
15-second idle timer resets only on actual newly admitted body bytes; tiny data
that violates the absolute 300-second deadline still fails. Client timestamps
and proxy retry timing are never authoritative.

The gateway uses bounded worker/connection/body-parser/sandbox-job pools and
the global anonymous abuse controls from `docs/22`, without IP, User-Agent,
cookie, TLS fingerprint, or device bucketing. Queue saturation returns one
generic non-cacheable unavailable response before attempt ownership/security
services where possible. It never raises body limits, enables buffering, skips
CAPTCHA, or accepts files without sandbox capacity.

## Failure and cleanup

| Failure | Required result |
|---|---|
| Declared body over 21 MiB | Reject at first ingress without upstream/body spool |
| Actual bytes differ from Content-Length | Terminate request and sandbox jobs |
| Malformed/ambiguous HTTP or multipart | Reject before submission acceptance |
| Unknown/duplicate/oversized/reordered part | Reject whole request; no partial report |
| File exceeds 5 MiB | Stop its stream immediately; destroy sandbox job |
| Aggregate files exceed 20 MiB | Reject even if individual files fit |
| Timeout/idle/disconnect | Abort attempt ownership as specified; destroy plaintext jobs |
| Proxy/upstream failure | No automatic POST replay and no alternate weaker path |
| Sandbox capacity/unavailability | Attachments/submission fail closed |
| CSRF/challenge/attempt invalid | No report pipeline; generic controlled response |
| Parser/handler internal exception | No sensitive locals/raw error in logs; cleanup and fail closed |

Cleanup is idempotent and keyed only by server-generated attempt/job IDs. It
closes input streams, cancels sandbox capabilities, destroys microVMs, and
removes any encrypted provisional artifact according to `docs/20`/`29`. Unknown
cleanup state never causes retry of browser bytes or acceptance of a partial
submission.

## Required tests before enablement

- exact `21 MiB - 1`, `21 MiB`, and `21 MiB + 1` bodies at every ingress layer;
- every file/sum/text/control/header/part/boundary limit at `N-1`, `N`, `N+1`;
- missing/duplicate/conflicting length/type, chunked/encoded/Expect/trailer,
  HTTP/1↔HTTP/2 translation, CL/TE and malformed-framing differential corpus;
- CRLF/boundary/preamble/epilogue/nesting/duplicate-name/filename*/header
  parameter/order/truncation/polyglot multipart corpus;
- slow header, idle body, slow continuous body, disconnect, upstream reset,
  proxy retry, pool exhaustion, and simultaneous-attempt races;
- instrumented proxy/container/host filesystem proves no request-body temporary
  file, buffer spill, WAF capture, APM body, queue copy, or backup artifact;
- instrumented Django proves only the custom handler runs, maximum memory stays
  bounded, file bytes never reach request objects/views/models/logs, and CSRF
  middleware still decides the exact token correctly;
- failure at every chunk/part/sandbox/audit/key/staging boundary cleans the one
  attempt without accepting a partial report or duplicating a retry;
- reporter-facing responses/logs remain generic and contain none of the
  forbidden request/header/body/filename/metadata values.

## Consolidated decisions awaiting the pre-code gate

1. exact 21 MiB encoded-body and 20 MiB aggregate-file ceilings;
2. closed `Content-Length`-required, uncompressed, non-chunked multipart profile;
3. 12 parts, four files, 32 KiB control and multipart-header aggregate limits;
4. 10-second headers, 15-second idle, and 300-second absolute body deadlines;
5. streaming proxy with no disk/retry/body capture;
6. one custom bounded Django sandbox-streaming upload handler and no default
   memory/temporary handlers;
7. whole-request rejection and idempotent sandbox cleanup on every ambiguity;
8. production-equivalent CSRF/multipart/proxy desynchronization and no-spool PoC.

Independent HTTP request-smuggling/proxy review, exact proxy and Django version
configuration, custom-handler code review, production no-spool evidence,
sandbox capacity/DoS testing, and all dependent CAPTCHA/file/crypto/audit/Key
Service gates remain release blockers after owner approval.

## External design references

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 7578 — multipart/form-data](https://www.rfc-editor.org/rfc/rfc7578.html)
- [Django file uploads](https://docs.djangoproject.com/en/5.2/topics/http/file-uploads/)
