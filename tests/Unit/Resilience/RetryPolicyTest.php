<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Resilience;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Resilience\RetryPolicy;

class RetryPolicyTest extends TestCase
{
    public function testSuccessfulOperationDoesNotRetry(): void
    {
        $attempts = 0;
        $policy = RetryPolicy::exponentialBackoff(3);

        $result = $policy->execute(function () use (&$attempts) {
            $attempts++;
            return 'success';
        });

        $this->assertSame('success', $result);
        $this->assertSame(1, $attempts);
    }

    public function testRetriesOnFailure(): void
    {
        $attempts = 0;
        $policy = RetryPolicy::constant(3, 0.01);

        try {
            $policy->execute(function () use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('fail');
            });
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame(3, $attempts);
    }

    public function testSucceedsAfterRetries(): void
    {
        $attempts = 0;
        $policy = RetryPolicy::constant(3, 0.01);

        $result = $policy->execute(function () use (&$attempts) {
            $attempts++;
            if ($attempts < 3) {
                throw new \RuntimeException('fail');
            }
            return 'success';
        });

        $this->assertSame('success', $result);
        $this->assertSame(3, $attempts);
    }

    public function testExponentialBackoffDelays(): void
    {
        $policy = RetryPolicy::exponentialBackoff(
            maxAttempts: 3,
            baseDelay: 1.0,
            maxDelay: 10.0,
            multiplier: 2.0
        );

        // Access delays via reflection
        $reflection = new \ReflectionClass($policy);
        $delayMethod = $reflection->getMethod('calculateDelay');
        $delayMethod->setAccessible(true);

        $delay1 = $delayMethod->invoke($policy, 1);
        $delay2 = $delayMethod->invoke($policy, 2);
        $delay3 = $delayMethod->invoke($policy, 3);

        // With multiplier 2.0: 1.0, 2.0, 4.0
        $this->assertEqualsWithDelta(1.0, $delay1, 0.5); // Allow jitter
        $this->assertEqualsWithDelta(2.0, $delay2, 1.0);
        $this->assertEqualsWithDelta(4.0, $delay3, 2.0);
    }

    public function testLinearBackoff(): void
    {
        $policy = RetryPolicy::linearBackoff(3, 0.1, 0.1);

        $reflection = new \ReflectionClass($policy);
        $delayMethod = $reflection->getMethod('calculateDelay');
        $delayMethod->setAccessible(true);

        $delay1 = $delayMethod->invoke($policy, 1);
        $delay2 = $delayMethod->invoke($policy, 2);
        $delay3 = $delayMethod->invoke($policy, 3);

        $this->assertEqualsWithDelta(0.1, $delay1, 0.05);
        $this->assertEqualsWithDelta(0.2, $delay2, 0.1);
        $this->assertEqualsWithDelta(0.3, $delay3, 0.15);
    }

    public function testConstantDelay(): void
    {
        $policy = RetryPolicy::constant(3, 0.5);

        $reflection = new \ReflectionClass($policy);
        $delayMethod = $reflection->getMethod('calculateDelay');
        $delayMethod->setAccessible(true);

        $delay1 = $delayMethod->invoke($policy, 1);
        $delay2 = $delayMethod->invoke($policy, 2);

        $this->assertSame(0.5, $delay1);
        $this->assertSame(0.5, $delay2);
    }

    public function testNoDelay(): void
    {
        $policy = RetryPolicy::noDelay(5);

        $reflection = new \ReflectionClass($policy);
        $delayMethod = $reflection->getMethod('calculateDelay');
        $delayMethod->setAccessible(true);

        $delay = $delayMethod->invoke($policy, 1);

        $this->assertSame(0.0, $delay);
    }

    public function testRetryOnlySpecificExceptions(): void
    {
        $attempts = 0;
        $policy = RetryPolicy::constant(3, 0.01)
            ->retryOn(\InvalidArgumentException::class);

        // Should NOT retry on RuntimeException
        try {
            $policy->execute(function () use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('not retryable');
            });
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame(1, $attempts);

        // Should retry on InvalidArgumentException
        $attempts = 0;
        try {
            $policy->execute(function () use (&$attempts) {
                $attempts++;
                throw new \InvalidArgumentException('retryable');
            });
        } catch (\InvalidArgumentException) {
            // Expected
        }

        $this->assertSame(3, $attempts);
    }

    public function testRetryWithCondition(): void
    {
        $attempts = 0;
        $policy = RetryPolicy::constant(3, 0.01)
            ->retryWhen(fn(\Throwable $e) => str_contains($e->getMessage(), 'retry'));

        // Should NOT retry
        try {
            $policy->execute(function () use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('do not repeat');
            });
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame(1, $attempts);

        // Should retry
        $attempts = 0;
        try {
            $policy->execute(function () use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('please retry');
            });
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame(3, $attempts);
    }

    public function testOnRetryCallback(): void
    {
        $retryLogs = [];
        $policy = RetryPolicy::constant(3, 0.01)
            ->onRetry(function (int $attempt, \Throwable $e) use (&$retryLogs) {
                $retryLogs[] = ['attempt' => $attempt, 'message' => $e->getMessage()];
            });

        try {
            $policy->execute(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertCount(2, $retryLogs); // 2 retries (not 3, first is not a retry)
        $this->assertSame(1, $retryLogs[0]['attempt']);
        $this->assertSame(2, $retryLogs[1]['attempt']);
    }

    public function testGetAttemptCount(): void
    {
        $policy = RetryPolicy::constant(5, 0.01);

        try {
            $policy->execute(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame(5, $policy->getLastAttemptCount());
    }
}
