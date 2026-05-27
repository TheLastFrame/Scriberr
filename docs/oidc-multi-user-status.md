# OIDC + Multi-user status

As of this change, **multi-user permission isolation is not fully implemented yet**.

What exists now:
- Optional OIDC token parsing/claim checks and middleware claim propagation.

What is still required for true multi-user isolation:
- Persist OIDC subject (`iss` + `sub`) to a local user record.
- Attach a stable internal `user_id` to every user-owned row.
- Enforce `user_id` filters in all repository read/update/delete queries.
- Ensure handlers derive ownership from auth context only (never client-supplied IDs).
- Add authorization tests proving User A cannot access User B data.

This document is intentionally explicit to avoid ambiguity when reviewing current auth behavior.
