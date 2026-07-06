<?php

declare(strict_types=1);

namespace Hydra\Csrf\Tests\Unit;

use Hydra\Csrf\CsrfGuard;
use Hydra\Session\Stores\ArraySessionStore;
use PHPUnit\Framework\TestCase;

/**
 * The guard is exercised against the real in-memory ArraySessionStore — the same
 * reference backend the session package tests with — so these prove the actual
 * session read/write path, not a mock of it.
 */
final class CsrfGuardTest extends TestCase
{
    public function test_token_is_minted_once_and_stable(): void
    {
        $guard = new CsrfGuard(new ArraySessionStore);

        $first = $guard->token();
        $second = $guard->token();

        // Lazily minted, then stable for the life of the session.
        $this->assertNotSame('', $first);
        $this->assertSame($first, $second);
        // 32 bytes of entropy rendered as hex.
        $this->assertSame(64, strlen($first));
        $this->assertSame(1, preg_match('/^[0-9a-f]+$/', $first));
    }

    public function test_distinct_sessions_get_distinct_tokens(): void
    {
        $a = (new CsrfGuard(new ArraySessionStore))->token();
        $b = (new CsrfGuard(new ArraySessionStore))->token();

        $this->assertNotSame($a, $b);
    }

    public function test_validate_accepts_the_minted_token(): void
    {
        $guard = new CsrfGuard(new ArraySessionStore);
        $token = $guard->token();

        $this->assertTrue($guard->validate($token));
    }

    public function test_validate_rejects_a_wrong_token(): void
    {
        $guard = new CsrfGuard(new ArraySessionStore);
        $guard->token();

        $this->assertFalse($guard->validate('not-the-token'));
    }

    public function test_validate_rejects_null_and_empty(): void
    {
        $guard = new CsrfGuard(new ArraySessionStore);
        $guard->token();

        $this->assertFalse($guard->validate(null));
        $this->assertFalse($guard->validate(''));
    }

    public function test_validate_is_false_before_any_token_is_minted(): void
    {
        // No token has been issued for this session, so nothing can validate —
        // not even a plausible-looking value. validate() must not mint one.
        $store = new ArraySessionStore;
        $guard = new CsrfGuard($store);

        $this->assertFalse($guard->validate('anything'));
        $this->assertFalse($guard->validate(bin2hex(random_bytes(32))));
    }

    public function test_rotate_returns_a_fresh_token(): void
    {
        $guard = new CsrfGuard(new ArraySessionStore);
        $old = $guard->token();

        $new = $guard->rotate();

        // A genuinely new token, well-formed like any minted one, and now the
        // stable one for the session.
        $this->assertNotSame($old, $new);
        $this->assertSame(64, strlen($new));
        $this->assertSame($new, $guard->token());
    }

    public function test_rotate_invalidates_the_old_token_and_honours_the_new(): void
    {
        // The login-rotation use case: after rotate(), a token captured before
        // authentication must stop validating, while the fresh one works.
        $guard = new CsrfGuard(new ArraySessionStore);
        $old = $guard->token();

        $new = $guard->rotate();

        $this->assertFalse($guard->validate($old));
        $this->assertTrue($guard->validate($new));
    }

    public function test_a_second_guard_on_the_same_session_shares_the_token(): void
    {
        // The guard is stateless: all state lives in the session, so a separate
        // instance (e.g. the one in the view vs the one in the middleware) reads
        // and validates the very same token.
        $store = new ArraySessionStore;
        $minted = (new CsrfGuard($store))->token();

        $this->assertTrue((new CsrfGuard($store))->validate($minted));
    }
}
