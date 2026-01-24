<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\RateLimiting;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\RateLimiting\RateLimiter;
use Senza1dio\SecurityShield\Tests\Fixtures\InMemoryStorage;

class RateLimiterTest extends TestCase
{
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function testSlidingWindowAllowsWithinLimit(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 10, 60);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed, "Request $i should be allowed");
        }
    }

    public function testSlidingWindowBlocksOverLimit(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 5, 60);

        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        $result = $limiter->attempt('user:123');

        $this->assertFalse($result->allowed);
        $this->assertGreaterThan(0, $result->retryAfter);
    }

    public function testFixedWindowAllowsWithinLimit(): void
    {
        $limiter = RateLimiter::fixedWindow($this->storage, 10, 60);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);
    }

    public function testTokenBucketAllowsWithTokens(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 10, 1.0);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }
    }

    public function testTokenBucketBlocksWhenEmpty(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 5, 1.0);

        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);
    }

    public function testTokenBucketRefillsOverTime(): void
    {
        $limiter = RateLimiter::tokenBucket($this->storage, 5, 5.0); // 5 tokens per second

        // Use all tokens
        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        // Wait for refill
        usleep(500000); // 0.5 seconds = 2.5 tokens

        // Should have some tokens now
        $result = $limiter->attempt('user:123');
        $this->assertTrue($result->allowed);
    }

    public function testLeakyBucketAllowsWithinCapacity(): void
    {
        $limiter = RateLimiter::leakyBucket($this->storage, 10, 1.0);

        for ($i = 0; $i < 10; $i++) {
            $result = $limiter->attempt('user:123');
            $this->assertTrue($result->allowed);
        }
    }

    public function testLeakyBucketBlocksWhenFull(): void
    {
        // Use a very low leak rate (0.01 req/sec) to ensure bucket doesn't drain
        // during test execution. This makes the test timing-independent.
        $limiter = RateLimiter::leakyBucket($this->storage, 5, 0.01);

        for ($i = 0; $i < 5; $i++) {
            $limiter->attempt('user:123');
        }

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);
    }

    public function testDifferentIdentifiersAreIndependent(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:1');
        $limiter->attempt('user:1');

        $result1 = $limiter->attempt('user:1');
        $result2 = $limiter->attempt('user:2');

        $this->assertFalse($result1->allowed, 'User 1 should be rate limited');
        $this->assertTrue($result2->allowed, 'User 2 should not be affected');
    }

    public function testCheckDoesNotConsumeToken(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:123');

        // Check should not consume
        $check = $limiter->check('user:123');
        $this->assertTrue($check->allowed);
        $this->assertSame(1, $check->remaining);

        // Still have 1 remaining
        $attempt = $limiter->attempt('user:123');
        $this->assertTrue($attempt->allowed);

        // Now exhausted
        $final = $limiter->attempt('user:123');
        $this->assertFalse($final->allowed);
    }

    public function testRemainingCount(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 5, 60);

        $result = $limiter->attempt('user:123');
        $this->assertSame(4, $result->remaining);

        $result = $limiter->attempt('user:123');
        $this->assertSame(3, $result->remaining);

        $result = $limiter->attempt('user:123');
        $this->assertSame(2, $result->remaining);
    }

    public function testReset(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 2, 60);

        $limiter->attempt('user:123');
        $limiter->attempt('user:123');

        $result = $limiter->attempt('user:123');
        $this->assertFalse($result->allowed);

        $limiter->reset('user:123');

        $result = $limiter->attempt('user:123');
        $this->assertTrue($result->allowed);
    }

    public function testCustomKeyPrefix(): void
    {
        $limiter = RateLimiter::slidingWindow($this->storage, 10, 60, 'custom:prefix:');

        $limiter->attempt('user:123');

        // Check storage has correct key prefix
        $keys = $this->storage->keys();
        $this->assertNotEmpty($keys);
        $this->assertStringStartsWith('custom:prefix:', $keys[0]);
    }
}
