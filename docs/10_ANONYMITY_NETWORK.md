# 10 — Reporter Network Anonymity

## Endpoints

The project must support:

1. a Tor v3 Onion Service;
2. a conventional HTTPS site.

The two channels must not be represented as equivalent.

## Tor

The Onion Service is the preferred high-anonymity channel.

Reporter-facing guidance should encourage Tor usage.

## Conventional HTTPS

The platform must avoid storing reporter IP/User-Agent at the application/reverse-proxy logging layer.

However, conventional HTTPS cannot guarantee that network metadata is invisible to all infrastructure or network observers.

Documentation and UI must not claim "100% anonymous" for the conventional site.

## Third-party resources

Reporter-facing pages must not load unnecessary third-party:

- JavaScript;
- fonts;
- analytics;
- pixels;
- error tracking;
- CDNs;
- remote CAPTCHA;
- embedded media.

Use self-hosted static resources and restrictive CSP.

## JavaScript

JavaScript should be excluded where not needed.

The project should remain usable as far as practical with Tor Browser restrictive modes.

When JavaScript is available, ALTCHA self-hosted is the current candidate.

When JavaScript is disabled, the approved direction is a completely self-hosted server-side challenge with:

- single-use validation;
- brief expiry;
- global abuse controls;
- no IP/device fingerprinting;
- no third-party tracking.

The exact no-JavaScript CAPTCHA technology and expiry remain OPEN. Its anti-automation strength may be lower than ALTCHA and this difference must be documented honestly.

`docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md` contains the current proposed
server-side protocol, atomic single-use semantics, five-minute expiry, anonymous
global limits, and candidate assessment. It remains non-authorizing until its
owner decisions and dependent rendering/accessibility reviews are complete.

Tor Browser at the Safest level must remain usable once the no-JavaScript path is approved.

Do not weaken anonymity through fingerprinting merely to solve CAPTCHA.

Operations for which CAPTCHA is mandatory fail closed when challenge generation or verification is unavailable or invalid.

## Logging

Reporter access logs should be disabled or minimized so reporter IP/User-Agent are not persisted.

Infrastructure must be reviewed end to end so a "no IP logging" claim is not contradicted by upstream proxies or default web-server logs.
