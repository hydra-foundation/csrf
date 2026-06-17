# Hydra CSRF

Synchronizer-token CSRF protection: one secret token per session, compared in
constant time against whatever an unsafe request submits. State lives entirely
in the session, so the guard is stateless and the package ships **no**
`ServiceProvider` — the guard autowires from the session binding.

## How it works

`CsrfGuard::token()` mints the token lazily on first read (typically when a view
renders a form or the layout's meta tag) and returns the same value for the life
of the session. It's hex, so it's safe to embed in HTML attributes, JSON
(`hx-headers`), and headers without further encoding. `validate()` is read-only
— it compares with `hash_equals` and never mints.

`VerifyCsrfTokenMiddleware` lets safe methods (GET/HEAD/OPTIONS) through
untouched — a GET is what mints the token in the first place — and requires a
matching token on every POST/PUT/PATCH/DELETE, else a 403 before the request
reaches a controller. The token is read from the `X-CSRF-Token` header first
(htmx and AJAX clients send it automatically once the layout is wired) and falls
back to the `_token` form field.

> Place this middleware **inside** the session middleware in the stack — it
> needs the session started so the guard can read the stored token.

## Rotating

`SessionInterface::regenerate()` keeps the data, including this token, so the
token survives a session-id rotation. If you want a fresh token on login, clear
it there explicitly.
