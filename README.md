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

## Expired sessions: redirect instead of a bare 403

When a session expires (or its cookie is cleared) and the user then submits a
form they loaded earlier, the fresh session knows no token, so the middleware
rejects the POST — and without help the user sees a bare 403 where they
expected the login page.

The package's part is the **mechanism**: the middleware throws a distinct typed
exception, `Hydra\Csrf\Exceptions\TokenMismatchException` (a 403
`HttpException`), and never builds a response itself. What to DO about a
mismatch is **policy**, and policy belongs to the app — the package owns no
routes and cannot know where "log in" lives.

The recipe: an app middleware placed **outside** `VerifyCsrfTokenMiddleware`
(it can only catch what it wraps) but inside the session middleware catches the
exception and asks `CsrfGuard::issued()` — read-only, never mints — whether the
session has a token at all:

- **no token issued** → the session cannot possibly validate anything: the
  submit came from a form rendered by a session that no longer exists — the
  expired-session symptom. Redirect to the login page.
- **token issued but mismatched** → the session is alive and knows its token,
  so the bad submission is a real CSRF failure (or a page rendered before an
  explicit `rotate()`). Rethrow — the 403 is correct, and swallowing it would
  blunt the protection.

```php
public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
{
    try {
        return $handler->handle($request);
    } catch (TokenMismatchException $e) {
        if ($this->csrf->issued()) {
            throw $e; // a live session with a bad token IS a CSRF failure: 403
        }

        return $this->respond->redirect('/login'); // expired session: log in again
    }
}
```

Deciding by `issued()` (not by asking the auth guard whether a user is logged
in) keeps the policy middleware session-only and cheap: resolving the auth
guard would drag the app's user provider — and its database connection — into
every request just to serve a catch block that almost never fires. The
reference app's `RedirectUnauthenticatedMiddleware` implements exactly this
recipe (folded into the same middleware that maps auth's 401 to a redirect).
