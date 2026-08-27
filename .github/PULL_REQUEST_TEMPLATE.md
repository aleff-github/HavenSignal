## Summary

Describe the smallest bounded change in this pull request.

## Applicable requirements / specifications

List the relevant `docs/` files and requirement IDs, if applicable.

## Trust boundaries touched

Describe any process, role, data-store, cryptographic, network, or authorization boundary affected.

## Data impact

What data can this change create, read, persist, log, encrypt, decrypt, export, or delete?

## Failure behavior

Explain fail-closed behavior and what happens when dependencies are unavailable.

## Tests

- [ ] Happy-path tests added/updated where applicable
- [ ] Negative/abuse tests added/updated where applicable
- [ ] Concurrency/replay/stale-state tests considered where applicable
- [ ] `python manage.py check`
- [ ] `python manage.py test -v 2`

## Security checklist

- [ ] No real sensitive data or production secrets
- [ ] No reporter-controlled content added to logs
- [ ] No new external telemetry on sensitive surfaces
- [ ] No weaker fallback mode introduced
- [ ] No reporter account/authentication/chat/AI decision-making added
- [ ] Security-sensitive design is already authorized, or this PR is documentation-only
- [ ] Relevant documentation is updated

## Reviewer notes

Call out any assumption that requires an explicit project-owner or independent-security-review decision.
