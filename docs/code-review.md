# Community code review — November 19, 2026

This was a focused review of the Community source, not a security certification or an email-client compatibility claim. The personal installation was outside the change scope.

## Fixes in this change

### Missing OIDC signing keys could crash the callback

A provider returning `{}` from its JWKS endpoint caused Authlib's key import to raise `KeyError('keys')`. The callback handled OAuth and JOSE errors, but not this malformed-response error, so the browser received a 500.

The callback now rejects malformed responses with a 401 and leaves the user signed out. Logs include the safe exception class and category without logging the exception message, token, or provider response. Tests reproduce missing-key and malformed-response failures.

### The OIDC connection test didn't test signing keys

The test previously checked discovery and endpoint URLs, so a provider with an empty or invalid JWKS could pass setup and fail only at first login. It now fetches the advertised HTTPS JWKS, checks for a nonempty key set, and imports it with the same JOSE library used for token verification. Missing keys produce an actionable setup error. Non-object discovery data and malformed keys are rejected rather than causing an attribute or key error.

This still doesn't test client credentials, user assignment, or a complete login. The admin guide makes that distinction explicit. Authentik's RSA Signing Key requirement and metadata-cache restart step are documented.

## Follow-up work

| Priority | Finding | Suggested next step |
| --- | --- | --- |
| Medium | Signature/profile saves have no stale-revision check. Two open editors can overwrite one another's saved draft. Installation settings already have a revision check. | Add optimistic concurrency to draft/profile saves, with a clear reload-or-save-copy flow and a two-session regression test. Keep this separate from documentation changes. |
| Medium | JSON bodies are parsed before field validation. Block counts and HTML/image sizes are capped, but there is no general JSON request-body cap, and unknown content fields can be persisted. | Add endpoint-appropriate body limits and compatibility-aware content validation. Review existing exports before dropping fields. |
| Low | Record and profile list endpoints return full collections, including signature content, without pagination. | Add pagination or summary endpoints when larger workspaces justify it, and test selection/search behavior. |
| Low | The backend and editor are large files with mixed responsibilities. | Extract cohesive modules incrementally after adding behavioral coverage. Avoid formatting the entire project or replacing the editor during bug fixes. |
| Resolved | Public distribution license | MIT selected on November 20, 2026; see LICENSE and THIRD_PARTY_NOTICES.md. |

## Paths reviewed

- First-run setup, persistent keys, and SQLite initialization/migration.
- Local login, account identity, OIDC callback, discovery, LDAP bind/search, and provisioning.
- Admin/member authorization on users, profiles, templates, and signature reads/writes.
- HTML import sanitization, rendered previews, image validation, published snapshots, and ZIP export.
- Compose configuration, container startup, and the image-publishing workflow.

Existing controls retained include CSRF checks, issuer/subject identity matching, non-admin external provisioning, explicit admin roles, guarded record reads, encrypted stored provider secrets, verified directory TLS, escaped LDAP filters, safe HTML/link handling, and generated image paths. Those observations don't establish the absence of other bugs.

## Verification

- **37 automated tests passed** locally with Python 3.12.
- Ruff's `F` checks passed for `app/` and `tests/` (undefined names and unused imports/variables).
- README shell blocks passed shell syntax checks; its Compose example parsed as YAML.
- Screenshots were captured from the real UI in Chromium with fictional contacts and no configured provider secrets. The temporary server was stopped afterward.
- A fresh Docker build and deployment were not run locally: Docker isn't installed on this workstation. The pull-request workflow is responsible for container regression, Compose, and first-run/persistence checks.
- The new OIDC failure paths use mocks. A previous Authentik login succeeded in the Community test installation, but these source changes have not been deployed or tested through a new end-to-end SSO login.
- Direct LDAP/AD login and mail-client rendering were not tested against live clients in this review. See the [email-client checklist](../email-signature-compatibility-and-qa.md).
