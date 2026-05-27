# OIDC login flow status

Current status in backend:

- OIDC token **validation scaffold** is wired into `AuthService` and middleware path.
- Basic OIDC browser login flow is wired with:
  - `GET /api/v1/auth/oidc/start` (discovery + redirect to provider authorize endpoint)
  - `GET /api/v1/auth/oidc/callback` (state check + code exchange + local JWT issuance)
- Current API auth still uses local JWT for app session after OIDC callback.

Important limitation:
- OIDC verifier still needs full JWKS signature validation hardening; current scaffold behavior should be treated as transitional.
