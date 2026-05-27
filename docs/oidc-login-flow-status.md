# OIDC login flow status

Current status in backend:

- OIDC token **validation scaffold** is wired into `AuthService` and middleware path.
- A full OIDC browser login flow (**authorize redirect + callback + code exchange + session/cookie management**) is **not wired**.
- Current API auth still relies on bearer token validation paths.

Implication:
- You can configure OIDC verifier settings (including client credentials), but there is currently no end-user OIDC sign-in endpoint flow in this backend yet.
