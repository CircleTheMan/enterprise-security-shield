<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Circuit Breaker Pattern Implementation
 *
 * Prevents cascading failures by failing fast when a dependency is unhealthy.
 *
 * STATES:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Dependency is down, fail immediately without trying
 * - HALF_OPEN: Testing if dependency recovered, allow limited requests
 *
 * STATE TRANSITIONS:
 * ```
 * CLOSED --[failure threshold reached]--> OPEN
 * OPEN --[timeout elapsed]--> HALF_OPEN
 * HALF_OPEN --[success]--> CLOSED
 * HALF_OPEN --[failure]--> OPEN
 * ```
 *
 * USAGE:
 * ```php
 * $breaker = new CircuitBreaker('redis', $storage, [
 *     'failure_threshold' => 5,
 *     'recovery_timeout' => 30,
 *     'half_open_max_calls' => 3,
 * ]);
 *
 * $result = $breaker->call(
 *     fn() => $redis->get('key'),           // Primary operation
 *     fn() => $this->localCache->get('key') // Fallback
 * );
 * ```
 *
 * DISTRIBUTED STATE:
 * State is stored in Redis/DB so all instances share the same circuit state.
 * This prevents one instance from hammering a dead service while others have it open.
 *
 * @package Senza1dio\SecurityShield\Resilience
 */
class CircuitBreaker
{
    public const STATE_CLOSED = 'closed';
    public const STATE_OPEN = 'open';
    public const STATE_HALF_OPEN = 'half_open';

    private string $name;
    private ?StorageInterface $storage;
    private string $keyPrefix;

    // Configuration
    private int $failureThreshold;
    private int $recoveryTimeout;
    private int $halfOpenMaxCalls;
    private int $successThreshold;

    // In-memory state (fallback when no storage)
    private string $localState = self::STATE_CLOSED;
    private int $localFailureCount = 0;
    private int $localSuccessCount = 0;
    private ?int $localOpenedAt = null;
    private int $localHalfOpenCalls = 0;

    // Event callbacks
    /** @var array<callable> */
    private array $onStateChange = [];
    /** @var array<callable> */
    private array $onFailure = [];
    /** @var array<callable> */
    private array $onSuccess = [];

    /**
     * @param string $name Unique identifier for this circuit
     * @param StorageInterface|null $storage Shared storage for distributed state (null = local only)
     * @param array{
     *     failure_threshold?: int,
     *     recovery_timeout?: int,
     *     half_open_max_calls?: int,
     *     success_threshold?: int,
     *     key_prefix?: string
     * } $options Configuration options
     */
    public function __construct(
        string $name,
        ?StorageInterface $storage = null,
        array $options = []
    ) {
        $this->name = $name;
        $this->storage = $storage;
        $this->keyPrefix = $options['key_prefix'] ?? 'circuit_breaker:';

        // Configuration with sensible defaults
        $this->failureThreshold = $options['failure_threshold'] ?? 5;
        $this->recoveryTimeout = $options['recovery_timeout'] ?? 30;
        $this->halfOpenMaxCalls = $options['half_open_max_calls'] ?? 3;
        $this->successThreshold = $options['success_threshold'] ?? 2;
    }

    /**
     * Execute operation through the circuit breaker
     *
     * @template T
     * @param callable(): T $operation Primary operation to execute
     * @param callable(): T|null $fallback Fallback when circuit is open (optional)
     * @return T Result of operation or fallback
     * @throws CircuitOpenException When circuit is open and no fallback provided
     * @throws \Throwable When operation fails and circuit allows propagation
     */
    public function call(callable $operation, ?callable $fallback = null): mixed
    {
        $state = $this->getState();

        // OPEN: Fail fast
        if ($state === self::STATE_OPEN) {
            if ($this->shouldAttemptRecovery()) {
                $this->transitionTo(self::STATE_HALF_OPEN);
            } else {
                return $this->handleOpenCircuit($fallback);
            }
        }

        // HALF_OPEN: Check if we've exceeded test calls
        if ($state === self::STATE_HALF_OPEN) {
            $halfOpenCalls = $this->getHalfOpenCalls();
            if ($halfOpenCalls >= $this->halfOpenMaxCalls) {
                return $this->handleOpenCircuit($fallback);
            }
            $this->incrementHalfOpenCalls();
        }

        // Execute operation
        try {
            $result = $operation();
            $this->recordSuccess();
            return $result;
        } catch (\Throwable $e) {
            $this->recordFailure($e);

            // In HALF_OPEN, single failure reopens circuit
            if ($this->getState() === self::STATE_HALF_OPEN) {
                $this->transitionTo(self::STATE_OPEN);
            }

            // If we have a fallback, use it
            if ($fallback !== null) {
                return $fallback();
            }

            throw $e;
        }
    }

    /**
     * Get current circuit state
     */
    public function getState(): string
    {
        if ($this->storage === null) {
            return $this->localState;
        }

        $state = $this->storage->get($this->getKey('state'));
        return is_string($state) ? $state : self::STATE_CLOSED;
    }

    /**
     * Get failure count
     */
    public function getFailureCount(): int
    {
        if ($this->storage === null) {
            return $this->localFailureCount;
        }

        $count = $this->storage->get($this->getKey('failures'));
        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Get success count (in half-open state)
     */
    public function getSuccessCount(): int
    {
        if ($this->storage === null) {
            return $this->localSuccessCount;
        }

        $count = $this->storage->get($this->getKey('successes'));
        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Get half-open call count
     */
    public function getHalfOpenCalls(): int
    {
        if ($this->storage === null) {
            return $this->localHalfOpenCalls;
        }

        $count = $this->storage->get($this->getKey('half_open_calls'));
        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Check if circuit is allowing requests
     */
    public function isAvailable(): bool
    {
        $state = $this->getState();

        if ($state === self::STATE_CLOSED) {
            return true;
        }

        if ($state === self::STATE_OPEN) {
            return $this->shouldAttemptRecovery();
        }

        // HALF_OPEN: Limited availability
        return $this->getHalfOpenCalls() < $this->halfOpenMaxCalls;
    }

    /**
     * Force circuit to open state (manual trip)
     */
    public function forceOpen(): void
    {
        $this->transitionTo(self::STATE_OPEN);
    }

    /**
     * Force circuit to closed state (manual reset)
     */
    public function forceClose(): void
    {
        $this->transitionTo(self::STATE_CLOSED);
        $this->resetCounters();
    }

    /**
     * Get circuit statistics
     *
     * @return array{
     *     name: string,
     *     state: string,
     *     failure_count: int,
     *     success_count: int,
     *     failure_threshold: int,
     *     recovery_timeout: int,
     *     time_until_recovery: int|null,
     *     half_open_calls: int
     * }
     */
    public function getStatistics(): array
    {
        $state = $this->getState();
        $timeUntilRecovery = null;

        if ($state === self::STATE_OPEN) {
            $openedAt = $this->getOpenedAt();
            if ($openedAt !== null) {
                $elapsed = time() - $openedAt;
                $timeUntilRecovery = max(0, $this->recoveryTimeout - $elapsed);
            }
        }

        return [
            'name' => $this->name,
            'state' => $state,
            'failure_count' => $this->getFailureCount(),
            'success_count' => $this->getSuccessCount(),
            'failure_threshold' => $this->failureThreshold,
            'recovery_timeout' => $this->recoveryTimeout,
            'time_until_recovery' => $timeUntilRecovery,
            'half_open_calls' => $this->getHalfOpenCalls(),
        ];
    }

    /**
     * Register callback for state changes
     *
     * @param callable(string $oldState, string $newState, string $circuitName): void $callback
     */
    public function onStateChange(callable $callback): self
    {
        $this->onStateChange[] = $callback;
        return $this;
    }

    /**
     * Register callback for failures
     *
     * @param callable(\Throwable $e, int $failureCount, string $circuitName): void $callback
     */
    public function onFailure(callable $callback): self
    {
        $this->onFailure[] = $callback;
        return $this;
    }

    /**
     * Register callback for successes
     *
     * @param callable(int $successCount, string $circuitName): void $callback
     */
    public function onSuccess(callable $callback): self
    {
        $this->onSuccess[] = $callback;
        return $this;
    }

    // ==================== PRIVATE METHODS ====================

    private function recordSuccess(): void
    {
        $state = $this->getState();

        if ($state === self::STATE_HALF_OPEN) {
            $successCount = $this->incrementSuccessCount();

            // Emit success event
            foreach ($this->onSuccess as $callback) {
                $callback($successCount, $this->name);
            }

            // If enough successes, close the circuit
            if ($successCount >= $this->successThreshold) {
                $this->transitionTo(self::STATE_CLOSED);
                $this->resetCounters();
            }
        } elseif ($state === self::STATE_CLOSED) {
            // Reset failure count on success in closed state
            $this->resetFailureCount();

            foreach ($this->onSuccess as $callback) {
                $callback(0, $this->name);
            }
        }
    }

    private function recordFailure(\Throwable $e): void
    {
        $failureCount = $this->incrementFailureCount();

        // Emit failure event
        foreach ($this->onFailure as $callback) {
            $callback($e, $failureCount, $this->name);
        }

        // Check if threshold reached
        if ($failureCount >= $this->failureThreshold) {
            $this->transitionTo(self::STATE_OPEN);
        }
    }

    private function transitionTo(string $newState): void
    {
        $oldState = $this->getState();

        if ($oldState === $newState) {
            return;
        }

        // Log state transition for observability
        error_log(sprintf(
            "CircuitBreaker[%s]: State transition %s -> %s (failures=%d, threshold=%d)",
            $this->name,
            $oldState,
            $newState,
            $this->getFailureCount(),
            $this->failureThreshold
        ));

        // Update state
        if ($this->storage !== null) {
            $this->storage->set($this->getKey('state'), $newState, $this->recoveryTimeout * 2);
        } else {
            $this->localState = $newState;
        }

        // Record when opened
        if ($newState === self::STATE_OPEN) {
            $this->setOpenedAt(time());
        }

        // Reset half-open calls when entering half-open
        if ($newState === self::STATE_HALF_OPEN) {
            $this->resetHalfOpenCalls();
            $this->resetSuccessCount();
        }

        // Emit state change event
        foreach ($this->onStateChange as $callback) {
            $callback($oldState, $newState, $this->name);
        }
    }

    private function shouldAttemptRecovery(): bool
    {
        $openedAt = $this->getOpenedAt();

        if ($openedAt === null) {
            return true;
        }

        return (time() - $openedAt) >= $this->recoveryTimeout;
    }

    /**
     * @return mixed
     * @throws CircuitOpenException
     */
    private function handleOpenCircuit(?callable $fallback): mixed
    {
        if ($fallback !== null) {
            return $fallback();
        }

        throw new CircuitOpenException(
            "Circuit '{$this->name}' is open. Service unavailable.",
            $this->name,
            $this->getStatistics()
        );
    }

    private function getOpenedAt(): ?int
    {
        if ($this->storage === null) {
            return $this->localOpenedAt;
        }

        $timestamp = $this->storage->get($this->getKey('opened_at'));
        return is_numeric($timestamp) ? (int) $timestamp : null;
    }

    private function setOpenedAt(int $timestamp): void
    {
        if ($this->storage !== null) {
            $this->storage->set($this->getKey('opened_at'), (string) $timestamp, $this->recoveryTimeout * 2);
        } else {
            $this->localOpenedAt = $timestamp;
        }
    }

    private function incrementFailureCount(): int
    {
        if ($this->storage !== null) {
            return $this->storage->increment($this->getKey('failures'), 1, $this->recoveryTimeout * 2);
        }

        return ++$this->localFailureCount;
    }

    private function incrementSuccessCount(): int
    {
        if ($this->storage !== null) {
            return $this->storage->increment($this->getKey('successes'), 1, $this->recoveryTimeout * 2);
        }

        return ++$this->localSuccessCount;
    }

    private function incrementHalfOpenCalls(): int
    {
        if ($this->storage !== null) {
            return $this->storage->increment($this->getKey('half_open_calls'), 1, $this->recoveryTimeout * 2);
        }

        return ++$this->localHalfOpenCalls;
    }

    private function resetFailureCount(): void
    {
        if ($this->storage !== null) {
            $this->storage->delete($this->getKey('failures'));
        } else {
            $this->localFailureCount = 0;
        }
    }

    private function resetSuccessCount(): void
    {
        if ($this->storage !== null) {
            $this->storage->delete($this->getKey('successes'));
        } else {
            $this->localSuccessCount = 0;
        }
    }

    private function resetHalfOpenCalls(): void
    {
        if ($this->storage !== null) {
            $this->storage->delete($this->getKey('half_open_calls'));
        } else {
            $this->localHalfOpenCalls = 0;
        }
    }

    private function resetCounters(): void
    {
        $this->resetFailureCount();
        $this->resetSuccessCount();
        $this->resetHalfOpenCalls();

        if ($this->storage !== null) {
            $this->storage->delete($this->getKey('opened_at'));
        } else {
            $this->localOpenedAt = null;
        }
    }

    private function getKey(string $suffix): string
    {
        return $this->keyPrefix . $this->name . ':' . $suffix;
    }
}
