# Architecture checks

This package contains static, non-executing checks for the current inert
dependency boundaries. It is not a runtime sandbox, credential boundary, or
substitute for process/network isolation.

Run all current static policies with:

```bash
python -m architecture_checks .
```

The aggregate runner normalizes controlled, content-free violations from the
individual policies and returns a failing exit status when any policy fails.
It does not expand what the individual policies prove.

The repository-hygiene policy inspects only tracked path names and `.gitignore`
rules. It rejects committed local databases, logs, virtual environments,
secret/config material, export artifacts, temporary workspaces, quarantine
areas, user media, collected static output, and test/cache artifacts. It is not
a content scanner or secret scanner and never reads or echoes candidate file
contents.

The verification-script policy parses, but never executes, `scripts/verify`.
It locks the reviewed command order for architecture checks, Django system
checks, migration drift checks, the Django test suite, Python compilation, and
manifest validation. Removing a required step, changing the executable source,
or making the script unavailable fails closed with controlled reason codes.

The CI-workflow policy parses `.github/workflows/ci.yml` as text without
executing it. It fixes read-only repository permissions, pinned checkout and
setup-python actions, Python 3.13, locked dependency installation with
`--require-hashes`, and delegation to `scripts/verify`. Write permissions,
unpinned moving action refs, un-hashed dependency installation, and
`continue-on-error` fail closed.

The reporter policy is an exact allowlist of imports used by the current
read-only Reporter Gateway and root URL configuration. Any new absolute import
requires an explicit reviewed policy change. Local single-level relative
imports are allowed only inside `reporter_gateway`; parent-relative imports,
star imports, dynamic imports, `eval`, and `exec` are rejected.

The surface policy also parses, but never imports or renders, the current
development settings, root URL configuration, landing-page template, and CSS.
It fixes the inert installed-app/middleware profile, the single home route, a
closed passive HTML/attribute/directive subset, and CSS with no resource-loading
or legacy active-content constructs. Missing, dynamic, mutated, malformed,
unreadable, or out-of-root inputs fail closed with controlled reason codes.

The same policy locks the executable AST of the reporter view and response-
header middleware. A new endpoint, unsafe method, request-derived render
context, cookie, logging operation, relaxed cache/CSP/header behavior, or any
other executable change requires an explicit policy update. The files are
parsed but never imported or executed.

The lifecycle-migration policy parses the sole inert initial migration without
importing it. It fixes the empty dependency graph, exact model/field/type and
operation sequence, closed migration/model constructor calls, and absence of
additional numbered migrations. A separate Django drift test requires
`makemigrations --check --dry-run` to report no model changes.

The submission-migration policy likewise parses but never imports or executes
the sole `submission_workflow` migration. Its complete executable AST, empty
dependency graph, exact metadata-only fields, constraints, state/version shape,
timestamps, imports, and sole numbered-file set are fixed. Any schema, state,
constraint, data/SQL/custom-code, dynamic, import, or graph change requires an
explicit policy update, while malformed and out-of-root inputs fail closed.

The submission-source policy locks the complete executable AST of
`submission_workflow/errors.py`, `states.py`, `transitions.py`, and `models.py`.
It fixes the generic controlled error, closed state/edge registry, monotonic
server-time planner, metadata-only schema constraints, creation-only model
behavior, and absence of a protected persistence executor. Added states,
backward edges, sensitive fields, logging, caller-selected time, database
capability, weakened constraints, or success paths require explicit review.

The lifecycle-source policy locks the complete executable AST of
`report_lifecycle/errors.py`, `states.py`, `transitions.py`, `bindings.py`,
`models.py`, and `persistence.py`. It fixes controlled failures, closed state
graphs, server-time lease rules, monotonic versions/generations, exact
report/lease/operation fencing, metadata-only constraints, creation-only model
behavior, the PostgreSQL capability gate, and the always-unavailable executor.
New content fields, weaker fencing, relaxed timeouts, logging, database writes,
or success paths require explicit review.

The bootstrap-source policy locks the complete executable AST of `manage.py`,
the ASGI/WSGI entrypoints, and both installed metadata-app `AppConfig` modules.
It fixes the settings-module identity, standard Django application factories,
management-command boundary, app identities, and absence of startup hooks.
Added logging, network, file, wrapper, alternate-settings, early-execution, or
`ready()` behavior requires explicit review without executing an entrypoint.

The initializer-source policy locks the complete executable AST of the current
application and migration package `__init__.py` files. It fixes passive package
markers and the reviewed `security_interfaces` re-export surface. Added imports,
exports, startup side effects, migration initializer code, dynamic behavior,
unknown targets, malformed source, and missing roots fail closed without
importing, executing, or echoing the initializer source.

The orchestration-source policy parses only `report_lifecycle/finalization.py`,
`report_lifecycle/deletion.py`, `report_lifecycle/retention.py`,
`report_lifecycle/cleanup.py`, `report_lifecycle/metadata_retention.py`, and
`report_lifecycle/audit_retention.py`. It fixes their exact imports, top-level members,
content-free immutable snapshot/plan fields, false capability flags, closed
call/raise allowlists, and executors whose only outcome is the reviewed
unavailable exception. Nested imports, database/network/crypto/I/O/logging/
scheduler calls, dynamic or mutating syntax, binding shadowing, and altered
executor bodies fail closed. Retention and cleanup alone may obtain server time
and normalize an aware timestamp to UTC through their exact allowlisted
`django.utils.timezone` calls.

The descriptor-source policy parses only
`security_interfaces/administrative_step_up_descriptors.py`. It fixes the
version-2 constants, imports, top-level members, immutable class profiles,
validator bodies, and closed call set. Added authentication, persistence,
network, file, logging, dynamic, or authorization behavior fails closed without
importing or executing the descriptor module.

The audit-descriptor source policy parses only
`security_interfaces/audit_descriptors.py` and compares its complete executable
AST with the reviewed inert audit-v1 profile. Registry, field, validator,
authorization-window, import, call, success-return, or side-effect changes fail
closed without importing, executing, or echoing the target source.

The alert-descriptor source policy applies the same non-executing exact-AST
boundary to `security_interfaces/alert_descriptors.py`. It makes every change to
the alert/severity/delivery registry, content-free fields, validators, false
durability/authorization results, imports, or effects an explicit review event.

The CAPTCHA-descriptor source policy locks the complete executable AST of
`security_interfaces/captcha_descriptors.py`. Exact no-JavaScript protocol
version, identifier and answer shapes, form-scope size, expiry and cleanup
times, PNG bounds, purpose/state registries, anonymous global bucket limits,
open production gates, validators, false capability properties, imports, and
absence of challenge generation, media rendering, persistence, endpoint,
network-identity binding, third-party CAPTCHA, service calls, or authorization
behavior are reviewed source facts.

The request-admission descriptor source policy locks the complete executable
AST of `security_interfaces/request_admission_descriptors.py`. Exact
body/file/text/control/header/part/boundary/streaming/time limits, closed
method/content-type/file-slot registries, false capability properties, imports,
and absence of HTTP parsing, multipart parsing, Django upload-handler
installation, file-byte access, filename exposure, sandbox jobs, plaintext
persistence, endpoint acceptance, logging, or service calls are reviewed source
facts.

The report step-up source policy locks the complete executable AST of
`security_interfaces/step_up_descriptors.py`. Identifier/counter fields,
algorithm and purpose registries, timing, unused state, validators, and every
false verification/authorization result remain inert unless explicitly reviewed.

The recovery-descriptor source policy locks the complete executable AST of
`security_interfaces/recovery_descriptors.py`. Exact Ticket ID and Recovery
Secret sizes, encodings, alphabets, metadata-only verifier purpose, validators,
false capability properties, imports, and absence of generation, HMAC,
persistence, lookup, endpoint, logging, or authorization behavior are reviewed
source facts.

The response-crypto descriptor source policy locks the complete executable AST
of `security_interfaces/response_crypto_descriptors.py`. Exact response
algorithm/profile identifiers, key/nonce/tag/frame/envelope sizes, immutable
context-size shapes, AAD purpose, allowlisted key-operation names, false
capability properties, imports, and absence of canonicalization, CBOR, AEAD,
Key Service calls, persistence, logging, endpoint, or authorization behavior
are reviewed source facts.

The response-text descriptor source policy locks the complete executable AST of
`security_interfaces/response_text_descriptors.py`. Exact Unicode/NFC/LF/UTF-8
profile constants, scalar and byte limits, plain-text restrictions, conservative
link markers, content-free return shape, imports, and absence of retained text,
canonical bytes, digests, drafts, persistence, endpoint, or authorization
behavior are reviewed source facts.

The response-schema descriptor source policy locks the complete executable AST
of `security_interfaces/response_schema_descriptors.py`. Exact ordered AAD and
ciphertext-envelope field names, primitive categories, public constant values,
byte-size metadata, false capability properties, imports, and absence of CBOR,
stored context values, ciphertext, service calls, persistence, endpoint, or
authorization behavior are reviewed source facts.

The negative-capability policy parses only `security_interfaces/errors.py` and
`security_interfaces/unavailable.py`. It locks the controlled dependency/error
registry and every mandatory unavailable adapter to the exact executable AST
that raises the generic fail-closed error. Success returns, plaintext/development
fallbacks, added methods, logging, and other side effects require an explicit
reviewed policy change.

Passing these checks proves only source-level conformance for the exact files
that were scanned. It is not a complete HTML/CSS security parser, browser
behavior proof, PostgreSQL schema/durability proof, production migration
review, runtime sandbox, or semantic proof of a protected protocol. It does
not authorize a reporter form, persistence, protected service call,
authentication, recovery, upload, operator/admin route, or deployment
capability.
