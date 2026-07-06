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
matching token on **every other** method (POST/PUT/PATCH/DELETE, but also any
WebDAV or custom verb — the safe list is an allowlist, so unknown verbs fail
closed), else a 403 before the request reaches a controller. The token is read
from the `X-CSRF-Token` header first
(htmx and AJAX clients send it automatically once the layout is wired) and falls
back to the `_token` form field.

> Place this middleware **inside** the session middleware in the stack — it
> needs the session started so the guard can read the stored token.

## Rotating

OWASP recommends rotating the CSRF token on authentication. Note that
`SessionInterface::regenerate()` keeps the data, including this token, so the
token survives a session-id rotation — call `rotate()` explicitly:

```php
public function login(ServerRequestInterface $request): ResponseInterface
{
    // ... verify credentials ...

    $session->regenerate(); // new session id (fixation defence)
    $guard->rotate();       // new CSRF token (regenerate() alone keeps the old one)

    return redirect('/dashboard');
}
```

`rotate()` discards the stored token and mints, stores and returns a fresh one.
Tokens embedded in already-rendered pages stop validating immediately, so call
it where you're navigating anyway (the login POST handler).
