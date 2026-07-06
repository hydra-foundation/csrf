<?php

declare(strict_types=1);

namespace Hydra\Csrf;

use Hydra\Csrf\Exceptions\TokenMismatchException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Verifies the CSRF token on every state-changing request.
 *
 * Safe methods (GET/HEAD/OPTIONS — RFC 9110's read-only ones) pass straight
 * through: they cause no side effects, and it is a GET rendering a form that
 * mints the token in the first place. EVERY other method — POST/PUT/PATCH/
 * DELETE, but equally PROPFIND, PURGE, or any custom verb — must carry a token
 * matching the session's, or the request is rejected with a 403
 * {@see TokenMismatchException} before it ever reaches a controller.
 *
 * The check is an ALLOWLIST of safe methods, not a blocklist of unsafe ones,
 * so it fails closed: a verb the framework never anticipated is guarded by
 * default rather than silently waved through. A blocklist would let any
 * unlisted method (WebDAV verbs, proxy extensions, typos in a client) mutate
 * state without a token.
 *
 * The token is read from the {@see CsrfGuard::HEADER} header first (htmx and
 * other AJAX clients send it automatically once the layout is wired) and falls
 * back to the {@see CsrfGuard::FIELD} form field (a plain, non-JS POST).
 *
 * Place it INSIDE the session middleware in the stack: it needs the session
 * started so the guard can read the stored token.
 */
final class VerifyCsrfTokenMiddleware implements MiddlewareInterface
{
    /**
     * The RFC 9110 §9.2.1 safe (read-only) methods, exempt from the token
     * check. Anything NOT in this list requires a valid token — an allowlist
     * of known-safe verbs fails closed for verbs we have never heard of.
     */
    private const SAFE = ['GET', 'HEAD', 'OPTIONS'];

    public function __construct(private readonly CsrfGuard $guard) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (
            !in_array(strtoupper($request->getMethod()), self::SAFE, true)
            && !$this->guard->validate($this->submittedToken($request))
        ) {
            throw new TokenMismatchException;
        }

        return $handler->handle($request);
    }

    /**
     * The token the client submitted: the header if present, else the form
     * field, else null (nothing submitted — which never validates).
     */
    private function submittedToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine(CsrfGuard::HEADER);
        if ($header !== '') {
            return $header;
        }

        $body = $request->getParsedBody();
        if (is_array($body) && isset($body[CsrfGuard::FIELD]) && is_string($body[CsrfGuard::FIELD])) {
            return $body[CsrfGuard::FIELD];
        }

        return null;
    }
}
