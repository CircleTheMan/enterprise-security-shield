<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Resilience;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Resilience\CircuitBreaker;
use Senza1dio\SecurityShield\Resilience\CircuitOpenException;
use Senza1dio\SecurityShield\Tests\Fixtures\InMemoryStorage;

class CircuitBreakerTest extends TestCase
{
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function testStartsInClosedState(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test');

        $this->assertSame('closed', $breaker->getState());
    }

    public function testSuccessfulCallKeepsCircuitClosed(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test');

        $result = $breaker->call(fn() => 'success');

        $this->assertSame('success', $result);
        $this->assertSame('closed', $breaker->getState());
    }

    public function testOpensAfterFailureThreshold(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 3);

        // First 2 failures - still closed
        for ($i = 0; $i < 2; $i++) {
            try {
                $breaker->call(fn() => throw new \RuntimeException('fail'));
            } catch (\RuntimeException) {
                // Expected
            }
        }

        $this->assertSame('closed', $breaker->getState());

        // Third failure - opens
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());
    }

    public function testOpenCircuitThrowsException(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 1);

        // Trip the breaker
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->expectException(CircuitOpenException::class);
        $breaker->call(fn() => 'should not run');
    }

    public function testOpenCircuitUsesFallback(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 1);

        // Trip the breaker
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $result = $breaker->call(
            fn() => 'should not run',
            fn() => 'fallback value'
        );

        $this->assertSame('fallback value', $result);
    }

    public function testTransitionsToHalfOpenAfterRecoveryTimeout(): void
    {
        $breaker = new CircuitBreaker(
            $this->storage,
            'test',
            failureThreshold: 1,
            recoveryTimeout: 1
        );

        // Trip the breaker
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());

        // Wait for recovery
        sleep(2);

        // Should transition to half-open on next call
        $result = $breaker->call(fn() => 'recovered');

        $this->assertSame('recovered', $result);
        $this->assertSame('closed', $breaker->getState());
    }

    public function testHalfOpenReopensOnFailure(): void
    {
        $breaker = new CircuitBreaker(
            $this->storage,
            'test',
            failureThreshold: 1,
            recoveryTimeout: 1
        );

        // Trip and wait
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        sleep(2);

        // Fail again in half-open state
        try {
            $breaker->call(fn() => throw new \RuntimeException('still failing'));
        } catch (\RuntimeException) {
            // Expected
        }

        $this->assertSame('open', $breaker->getState());
    }

    public function testForceOpen(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test');

        $breaker->forceOpen();

        $this->assertSame('open', $breaker->getState());
    }

    public function testForceClose(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 1);

        // Trip the breaker
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $breaker->forceClose();

        $this->assertSame('closed', $breaker->getState());
    }

    public function testReset(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 1);

        // Trip the breaker
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $breaker->reset();

        $this->assertSame('closed', $breaker->getState());
        $this->assertSame(0, $breaker->getFailureCount());
    }

    public function testGetStats(): void
    {
        $breaker = new CircuitBreaker($this->storage, 'test', failureThreshold: 5);

        // Some successes
        $breaker->call(fn() => 'ok');
        $breaker->call(fn() => 'ok');

        // Some failures
        try {
            $breaker->call(fn() => throw new \RuntimeException('fail'));
        } catch (\RuntimeException) {
            // Expected
        }

        $stats = $breaker->getStats();

        $this->assertSame('closed', $stats['state']);
        $this->assertSame(1, $stats['failure_count']);
        $this->assertSame(5, $stats['failure_threshold']);
    }
}
