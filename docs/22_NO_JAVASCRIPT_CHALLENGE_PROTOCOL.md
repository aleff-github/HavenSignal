# 22 — No-JavaScript Self-Hosted Challenge Protocol

## Status

**PROPOSED — project-owner review required. No CAPTCHA-protected operation is
authorized by this document.**

This proposal selects the server-side protocol, expiry, one-time semantics,
anonymous abuse controls, and rendering boundary for the no-JavaScript path.
It does not approve submission, recovery, finalization, Emergency Export,
ALTCHA, a production deployment, or any dependent cryptographic/audit/file
construction.

## Governing requirements

This proposal applies primarily to:

- `SEC-ANON-001..004`;
- `SEC-CAPTCHA-001..004`;
- `SEC-BROWSER-001..002`;
- `SEC-INPUT-006` where request admission depends on challenge validation;
- the CSRF, logging, transaction, dependency, and error-handling rules in
  `docs/16_DEVELOPMENT_RULES_DJANGO.md`.

`docs/01_SECURITY_BASELINE.md` remains normative. A conflict stops
implementation and returns the decision to the project owner.

## Honest security objective

The no-JavaScript challenge is an abuse-friction control. It is not proof that
a reporter is human, an identity, an authentication factor, a confidentiality
control, or a substitute for CSRF, request-size limits, submission-attempt
state, recovery credentials, operator MFA, audit receipts, or authorization.

Image and audio challenges can be solved by machine learning or paid human
solvers. Avoiding IP/device fingerprinting deliberately reduces the service's
ability to distinguish one distributed bot from many reporters. This weaker
anti-automation property is accepted only because anonymity and metadata
minimization take priority.

The design aims to make each challenge:

- entirely self-hosted and usable without JavaScript;
- unbound to IP address, User-Agent, device, browser fingerprint, account,
  email, or phone;
- short-lived and non-sliding;
- consumed by the first verification attempt, whether correct or incorrect;
- bound to one operation and one short-lived anonymous form scope;
- concurrency-safe across multiple application processes;
- protected by global, purpose-specific abuse limits;
- absent from logs, audit, tracing, analytics, and historical backups.

## Candidate review and product decision

### `django-simple-captcha` is not approved for direct integration

The project evaluated `django-simple-captcha` because it is self-hosted,
server-rendered, and compatible with Django. It must not be installed or used
directly for the protected flows in its currently reviewed form.

Reasons:

1. PyPI currently presents `0.6.3`, while the later upstream `0.7.0` release
   adds consumption after an incorrect answer. The dependency source and
   distributable artifact are not yet one unambiguous locked baseline for this
   repository.
2. The `0.7.0` validation path queries the challenge and then deletes it as
   separate ORM operations without an explicit row lock. Two synchronized
   requests can therefore race before deletion.
3. The model uses an application-global challenge table and upstream logging/
   pool behavior that is broader than the minimal dedicated service profile
   required here.
4. Direct use would make upstream widget/model behavior the security boundary
   instead of the explicit deny-by-default `CaptchaService` interface already
   required by `docs/19_SECURITY_SERVICE_INTERFACES.md`.

The upstream package may be reconsidered later as a rendering reference, but
its validator, model, URLs, refresh endpoint, audio temporary-file behavior,
test mode, and fallback behavior are not approved implicitly.

### Proposed implementation boundary

Use a small project-owned, separately reviewable Challenge Service behind the
approved narrow CAPTCHA interface. Production credentials, network policy,
ephemeral storage, and logs are distinct from reporter, recovery, operator,
administrator, audit, key, and file-sandbox profiles.

The service may share the Python/Django codebase during development, but that
does not count as production separation. Reporter and Recovery Gateways may
only:

- issue one challenge for an allowlisted purpose and anonymous form scope;
- fetch that challenge's bounded image/audio representation;
- submit one candidate answer for atomic validation;
- receive a controlled `VALID`, `INVALID`, or `UNAVAILABLE` result.

They cannot list challenges, read expected answers, select arbitrary rows,
change expiry, reset consumption, obtain IP/device data, or turn a result for
one purpose/scope into authorization for another.

## Exact version-1 challenge

### Challenge identifier

Each challenge receives an independent 16-byte identifier from the operating
system cryptographic random source. The browser representation is strict,
unpadded RFC 4648 base64url: exactly 22 characters in `[A-Za-z0-9_-]`.

The identifier is an opaque, short-lived public resource locator, not an
authentication secret or report identifier. It may appear in the same-origin
image/audio path because the browser must fetch that representation, but all
reporter-facing proxy/application access logging remains disabled. It must not
appear in application logs, audit, alerts, tracing, analytics, or metrics.

Generation fails closed on random-source error, wrong length, or a repeated
database collision. Three consecutive collisions abort issuance with a
controlled internal event and no identifier value.

### Answer alphabet and lifetime

The version-1 answer is six independent characters selected uniformly with the
operating system cryptographic random source from:

```text
23456789ABCDEFGHJKLMNPQRSTUVWXYZ
```

The 32-symbol alphabet excludes visually ambiguous `0`, `1`, `I`, and `O` and
provides a nominal 30-bit answer space. The image shows uppercase characters.
Submitted answers must be exactly six uppercase ASCII characters from the same
alphabet. The service does not trim, case-fold, Unicode-normalize, or accept
alternate characters.

The challenge expires exactly five minutes after server-side issuance. The
expiry is non-sliding: image/audio fetches, page reloads, validation failures,
clock values submitted by the browser, and retries never extend it.

### Purpose and anonymous form scope

Every challenge is bound at issuance to one allowlisted purpose:

- `SUBMIT_REPORT`;
- `RECOVER_RESPONSE`;
- later operator purposes only after their own flow is approved.

It is also bound to one independent 16-byte anonymous form-scope identifier.
For submission, this is the approved submission-attempt context from
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`. Recovery requires its own
short-lived, one-form scope before that endpoint is implemented.

The scope is not an account, reporter identity, tracking cookie, IP binding,
Recovery Secret, Ticket ID, or cross-form identifier. It is carried only in
the POST body and controlled same-site state, never a URL, and expires with the
form/challenge. One scope may have at most one `READY` challenge. Issuing a
replacement consumes the previous challenge before the new one becomes ready.

## Rendering

### Visual representation

The Challenge Service pre-renders one bounded RGB PNG at issuance from only
server-generated challenge characters and rendering parameters:

- fixed canvas: 240 by 80 pixels;
- exactly six characters from the approved alphabet;
- a bundled, reviewed, checksum-pinned local font;
- bounded per-character placement and rotation;
- bounded locally generated lines/dots that do not encode reporter data;
- no EXIF, textual chunks, comments, timestamps, hostnames, random seeds,
  identifiers, or other metadata;
- maximum encoded size: 64 KiB.

The renderer uses a locked, security-supported Pillow release after dependency
review. It never parses reporter-controlled image, font, path, color, size,
format, metadata, or rendering instructions. The PNG is generated once and
served from the ephemeral challenge record so repeated fetches do not repeat
expensive rendering.

Rendering uncertainty, dependency failure, missing font, size overflow, or
unexpected output fails issuance closed. There is no plaintext question,
weaker math puzzle, remote CAPTCHA, or fixed development answer fallback.

### Accessibility

An audio alternative is required before production enablement. It must be
entirely self-hosted, generated only from bundled reviewed assets, streamed or
assembled in bounded memory, and create no temporary file. It uses the same
answer and therefore does not issue a second independently usable challenge.

The exact licensed voice assets, format, duration, anti-precomputation
variation, and accessibility test remain a dependent HIGH review item. Until
that item is approved, the no-JavaScript protected endpoints remain disabled;
image-only operation is not accepted as the production fallback.

Visual and audio resources use same-origin fixed routes, `GET`/`HEAD` only,
`Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, restrictive CSP, and no third-party content.
Unknown, expired, consumed, wrong-purpose, and malformed identifiers return the
same controlled non-cacheable missing-resource response.

## CSRF is a separate mandatory control

Every protected state-changing request remains POST-only and passes Django's
`CsrfViewMiddleware` with a server-rendered `{% csrf_token %}`. A valid CAPTCHA
does not compensate for a missing, invalid, fixed, cross-form, or unverified
CSRF token. SameSite is defense in depth, not a replacement for token
validation.

Production reporter CSRF cookies are host-only, use the strictest approved
SameSite setting compatible with the HTTPS and Onion profiles, and are never
used as reporter identity or long-lived tracking state. Exact Secure-cookie
behavior must be tested on both conventional HTTPS and the approved Tor v3
Onion deployment before release. No origin is broadly trusted merely to make a
challenge work.

CSRF failure occurs before challenge validation and does not disclose whether
the challenge, form scope, Ticket ID, Recovery Secret, or report exists.

## Atomic single-use validation

Challenge states are:

```text
READY -> CONSUMED
READY -> EXPIRED
```

There is no transition back to `READY` and no success/failure-specific stored
state visible to the caller.

For one candidate answer, the Challenge Service:

1. checks the purpose-specific global validation bucket;
2. starts a PostgreSQL transaction using server-authoritative time;
3. loads the exact challenge row with `SELECT ... FOR UPDATE`;
4. verifies `READY`, unexpired state, purpose, form scope, schema version, and
   fixed field lengths;
5. copies the expected server-generated answer into bounded process memory;
6. commits `CONSUMED` before deciding or returning the comparison result;
7. after the durable consumption commit, compares the exact six ASCII bytes
   using `hmac.compare_digest` and returns only the controlled result.

The service must not raise a validation exception inside the transaction in a
way that rolls back consumption. A crash after committed consumption but
before comparison/result loses the challenge and requires a new one; this is
the approved fail-closed availability outcome.

A concurrent second request waits for or observes the committed state and
returns `INVALID` without comparing the expected answer. Unknown and already
invalid challenges execute a bounded dummy-comparison path so obvious code-path
differences are reduced without claiming perfect timing equality.

SQLite is not a valid concurrency backend for these tests or production.
`TransactionTestCase`, multiple database connections, multiple application
processes, and synchronized parallel POSTs are required because ordinary
Django `TestCase` can conceal incorrect transaction usage.

## Anonymous global abuse controls

No IP address, User-Agent, ASN, geography, TLS fingerprint, canvas fingerprint,
device identifier, persistent cookie, or reporter account is used as a rate
key.

The proposed baseline uses centralized, server-time token buckets, atomically
updated across all Challenge Service replicas. Buckets are separate by public
purpose and action:

| Bucket | Capacity | Refill | Effect when empty |
|---|---:|---:|---|
| Issue `SUBMIT_REPORT` | 20 | 1 token / 2 seconds | No challenge created |
| Verify `SUBMIT_REPORT` | 20 | 1 token / 3 seconds | Challenge untouched; generic unavailable result |
| Issue `RECOVER_RESPONSE` | 20 | 1 token / 2 seconds | No challenge created |
| Verify `RECOVER_RESPONSE` | 20 | 1 token / 3 seconds | Challenge untouched; generic unavailable result |
| Fetch image/audio, per purpose | 120 | 2 tokens / second | Generic unavailable resource |

Token-bucket state uses no reporter data and is excluded from application
backups. Fixed-window counters, per-process memory counters, and caller-provided
time are not authoritative.

These global limits can be deliberately exhausted by one attacker, denying
service to all reporters. That is an explicit residual availability risk of
refusing identity/IP/device tracking. The system may alert on aggregate bucket
exhaustion using only purpose, bucket type, coarse count, and server time; it
must not add identifiers or network metadata to regain convenience.

Changing the numeric limits is a reviewed security/configuration change. The
UI and API do not expose exact remaining capacity, solver scores, or
fingerprinting-derived retry decisions.

## Data inventory and lifecycle

The dedicated ephemeral challenge record contains only:

- random challenge identifier;
- allowlisted purpose;
- random short-lived form scope;
- expected server-generated answer;
- pre-rendered bounded PNG and, after approval, bounded audio;
- issued and expiry server times;
- `READY`/`CONSUMED` state and monotonic version.

It contains no report text, attachment, original filename, Ticket ID, Recovery
Secret, Response Note, operator note, IP, User-Agent, header copy, cookie copy,
CSRF token, browser fingerprint, or raw submitted answer.

The submitted answer is held only long enough to validate exact length/alphabet
and perform the one comparison. It is never persisted. Challenge records are
deleted no later than 15 minutes after consumption or expiry. The ephemeral
store is excluded from historical backups and snapshots; a restore cannot make
an old challenge valid because server time and state remain authoritative.

Application/audit logs contain no challenge/scope identifier or answer. Only
aggregate controlled metrics and allowlisted result codes may be retained.
CAPTCHA success/failure is not a permanent audit event.

## Failure behavior

| Failure | Required result |
|---|---|
| Random source, renderer, font, or ephemeral store unavailable | No challenge; protected operation remains unavailable |
| Global issue bucket empty | No challenge row or representation created |
| Global validation bucket empty | Do not validate or consume; generic unavailable response |
| Malformed identifier/answer/scope/purpose | Generic invalid result; no alternate parser |
| Expired, consumed, unknown, or wrong-scope challenge | Generic invalid result; no state oracle |
| Concurrent validation | One transaction consumes; all other requests fail |
| Crash before consumption commit | Challenge remains `READY` only if the transaction fully rolled back |
| Crash after consumption commit | Challenge stays consumed; new challenge required |
| CSRF invalid | Reject before challenge validation; no CAPTCHA or target-state oracle |
| Challenge valid but downstream control unavailable | Downstream operation fails closed; CAPTCHA is not restored or replayed |
| Cleanup unavailable | Challenge remains unusable by expiry/state; retry deletion with controlled aggregate alerting |
| Test mode/fixed answer enabled outside isolated tests | Startup/deployment check fails closed |

## Required tests before enablement

Tests must prove:

- no JavaScript, third-party request, tracking pixel, remote font, analytics,
  telemetry, IP/UA logging, fingerprinting, or persistent browser storage;
- exact identifier/answer lengths and strict ASCII alphabets;
- five-minute non-sliding server-authoritative expiry;
- wrong answer consumes exactly once;
- correct answer consumes exactly once;
- purpose/scope transplant, replay, refresh reuse, stale page, and malformed
  input fail closed;
- synchronized parallel correct/incorrect/mixed attempts produce one consumer
  across multiple database connections and application processes;
- consumption persists when comparison is wrong or response delivery fails;
- SQLite is rejected for concurrency/security acceptance tests;
- CAPTCHA success never bypasses CSRF, submission attempt, recovery
  verification, state, MFA, audit receipt, or Key Service checks;
- absent/removed/random/cross-form CSRF tokens reject every protected POST;
- global token buckets are atomic across replicas and use no network identity;
- bucket exhaustion and dependency failures create no challenge or weaker
  fallback;
- PNG/audio responses are bounded, metadata-free, same-origin, non-cacheable,
  and contain no reporter-controlled data;
- expired/consumed records are deleted on schedule and absent from backups;
- raw submitted answers, identifiers, scopes, bodies, headers, and parsing
  errors never enter logs, audit, alerts, traces, or metrics;
- Tor Browser at Safest level can issue, render, refresh, and submit the
  challenge without JavaScript;
- the approved audio path passes accessibility review without temporary files.

## Decisions required for approval

The project owner must explicitly approve:

1. the honest limited security claim and the global-denial-of-service residual
   risk caused by refusing IP/device/identity tracking;
2. version-1 identifiers, six-character 32-symbol answers, strict parsing, and
   five-minute non-sliding expiry;
3. consumption on the first correct or incorrect attempt using PostgreSQL row
   locking, with challenge loss after a post-commit crash;
4. the purpose-specific global token-bucket limits in this document;
5. rejection of direct `django-simple-captcha` integration in favor of the
   narrow project-owned Challenge Service, with production remaining disabled
   until its pinned Pillow/font and self-hosted audio/accessibility reviews are
   complete.

Even after approval, no protected endpoint is authorized until its independent
submission/recovery/operator gates are closed.

## External design references

- [Django 5.2 — `select_for_update()`](https://docs.djangoproject.com/en/5.2/ref/models/querysets/#select-for-update)
- [Django 5.2 — CSRF protection](https://docs.djangoproject.com/en/5.2/howto/csrf/)
- [Django 5.2 — CSRF settings](https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-cookie-samesite)
- [`django-simple-captcha` releases](https://github.com/mbi/django-simple-captcha/releases)
- [`django-simple-captcha` 0.7.0 validation source](https://github.com/mbi/django-simple-captcha/blob/v0.7.0/captcha/fields.py)
- [OWASP Bot Management and Anti-Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html)
