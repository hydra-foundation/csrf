<?php

declare(strict_types=1);

namespace Hydra\Csrf;

use Hydra\Session\Contracts\SessionInterface;

/**
 * The synchronizer-token guard: one secret token per session, compared in
 * constant time against whatever an unsafe request submits.
 *
 * All of its state lives in the (already session-scoped) {@see SessionInterface},
 * so the guard itself is stateless — every instance reads and writes the one
 * token under the one session, and nothing needs to bind or share it. That is
 * why the package ships no ServiceProvider: the guard autowires from the session
 * binding, exactly as hydrakit/validation's stateless Validator does.
 *
 * The token is minted lazily on first {@see token()} (typically when a view
 * renders a form or the layout's meta tag) and is then stable for the life of
 * the session. On a privilege change (login), rotate it explicitly with
 * {@see rotate()} — regenerating the session id alone is not enough, because
 * {@see SessionInterface::regenerate()} keeps the data, this token included.
 */
final class CsrfGuard
{
    /** The form field a plain (non-htmx) POST carries the token in. */
    public const FIELD = '_token';

    /** The header an htmx/AJAX request carries the token in. */
    public const HEADER = 'X-CSRF-Token';

    /** Where the token lives in the session (leading-underscore: framework-reserved). */
    private const SESSION_KEY = '_csrf_token';

    /** Token entropy in bytes; 32 bytes → a 64-char hex string. */
    private const TOKEN_BYTES = 32;

    public function __construct(private readonly SessionInterface $session) {}

    /**
     * The session's CSRF token, minted on first read and stable thereafter.
     * Safe to call on every render — repeated calls within a session return the
     * same value. The token is hex, so it is safe to embed in HTML attributes,
     * JSON (hx-headers) and headers without further encoding.
     */
    public function token(): string
    {
        $token = $this->session->get(self::SESSION_KEY);

        if (!is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(self::TOKEN_BYTES));
            $this->session->set(self::SESSION_KEY, $token);
        }

        return $token;
    }

    /**
     * Discard the current token and mint, store and return a fresh one.
     *
     * OWASP recommends rotating the CSRF token on authentication (login,
     * privilege escalation) so a token a pre-auth attacker may have captured
     * cannot forge post-auth requests. Note that regenerating the session id
     * ({@see SessionInterface::regenerate()}) does NOT rotate this token — the
     * session data survives the id change — which is exactly why this method
     * exists: the session key is private, so without it an app would have to
     * hardcode '_csrf_token' to force a fresh one.
     *
     * Any token embedded in already-rendered pages stops validating the moment
     * this runs, so call it at the point you are navigating anyway (the login
     * POST handler, before rendering the next page).
     */
    public function rotate(): string
    {
        $this->session->remove(self::SESSION_KEY);

        return $this->token();
    }

    /**
     * Whether $submitted matches the session token, compared in constant time
     * with hash_equals so a mismatch leaks no timing signal.
     *
     * Returns false when nothing was submitted, or when no token has been minted
     * yet — a request can never validate against an absent token. Note this does
     * NOT mint a token (unlike {@see token()}): validation is read-only.
     */
    public function validate(?string $submitted): bool
    {
        if ($submitted === null || $submitted === '') {
            return false;
        }

        $token = $this->session->get(self::SESSION_KEY);

        if (!is_string($token) || $token === '') {
            return false;
        }

        return hash_equals($token, $submitted);
    }
}
