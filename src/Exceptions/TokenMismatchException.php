<?php

declare(strict_types=1);

namespace Hydra\Csrf\Exceptions;

use Hydra\Http\Exceptions\HttpException;
use Throwable;

/**
 * An unsafe request arrived without a valid CSRF token: HTTP 403.
 *
 * Like the http package's own NotFoundException, this is a typed HttpException
 * so the application's outermost ErrorHandlerMiddleware renders it consistently
 * — the guard middleware just throws, it never builds a response itself. The
 * message is developer-authored, so it is safe for the error handler to show.
 */
final class TokenMismatchException extends HttpException
{
    public function __construct(string $message = 'CSRF token mismatch.', ?Throwable $previous = null)
    {
        parent::__construct(403, $message, [], $previous);
    }
}
