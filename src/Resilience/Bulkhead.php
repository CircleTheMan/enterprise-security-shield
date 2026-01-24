<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Bulkhead Pattern Implementation
 *
 * Limits concurrent access to a resource to prevent resource exhaustion.
 * Like watertight compartments in a ship - failure in one doesn't sink the whole ship.
 *
 * USE CASES:
 * - Limit concurrent database connections
 * - Limit concurrent external API calls
 * - Limit concurrent file operations
 * - Protect shared resources from overload
 *
 * USAGE:
 * ```php
 * // Local bulkhead (single process)
 * $bulkhead = new Bulkhead('database', 10); // Max 10 concurrent
 *
 * $result = $bulkhead->execute(function() {
 *     return $this->heavyDatabaseOperation();
 * });
 *
 * // Distributed bulkhead (across processes/servers)
 * $bulkhead = new Bulkhead('external_api', 50, $redisStorage);
 * ```
 *
 * QUEUEING:
 * ```php
 * // With queue for overflow
 * $bulkhead = new Bulkhead('api', 10, null, [
 *     'queue_size' => 100,
 *     'queue_timeout' => 5.0,
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Resilience
 */
class Bulkhead
{
    private string $name;
    private int $maxConcurrent;
    private ?StorageInterface $storage;

    // Queue configuration
    private int $queueSize;
    private float $queueTimeout;

    // Local state (when no storage)
    private int $localActive = 0;
    private int $localQueued = 0;

    // Metrics
    private int $totalExecutions = 0;
    private int $totalRejections = 0;
    private int $totalQueueTimeouts = 0;

    /**
     * @param string $name Unique identifier for this bulkhead
     * @param int $maxConcurrent Maximum concurrent executions
     * @param StorageInterface|null $storage Shared storage for distributed bulkhead
     * @param array{
     *     queue_size?: int,
     *     queue_timeout?: float,
     *     key_prefix?: string
     * } $options Configuration options
     */
    public function __construct(
        string $name,
        int $maxConcurrent,
        ?StorageInterface $storage = null,
        array $options = []
    ) {
        $this->name = $name;
        $this->maxConcurrent = max(1, $maxConcurrent);
        $this->storage = $storage;

        $this->queueSize = $options['queue_size'] ?? 0;
        $this->queueTimeout = $options['queue_timeout'] ?? 5.0;
    }

    /**
     * Execute operation within bulkhead constraints
     *
     * @template T
     * @param callable(): T $operation Operation to execute
     * @return T Result of operation
     * @throws BulkheadFullException When bulkhead is at capacity and queue is full
     * @throws BulkheadTimeoutException When queue timeout exceeded
     */
    public function execute(callable $operation): mixed
    {
        // Try to acquire permit
        if (!$this->tryAcquire()) {
            // Check if we can queue
            if ($this->queueSize > 0 && $this->getQueuedCount() < $this->queueSize) {
                return $this->executeWithQueue($operation);
            }

            $this->totalRejections++;
            throw new BulkheadFullException(
                "Bulkhead '{$this->name}' is full. Max concurrent: {$this->maxConcurrent}",
                $this->name,
                $this->getStatistics()
            );
        }

        try {
            $this->totalExecutions++;
            return $operation();
        } finally {
            $this->release();
        }
    }

    /**
     * Try to execute, return null if bulkhead is full
     *
     * @template T
     * @param callable(): T $operation
     * @return T|null
     */
    public function tryExecute(callable $operation): mixed
    {
        if (!$this->tryAcquire()) {
            return null;
        }

        try {
            $this->totalExecutions++;
            return $operation();
        } finally {
            $this->release();
        }
    }

    /**
     * Check if bulkhead has capacity
     */
    public function hasCapacity(): bool
    {
        return $this->getActiveCount() < $this->maxConcurrent;
    }

    /**
     * Get number of active executions
     */
    public function getActiveCount(): int
    {
        if ($this->storage === null) {
            return $this->localActive;
        }

        $count = $this->storage->get($this->getKey('active'));
        return is_numeric($count) ? max(0, (int) $count) : 0;
    }

    /**
     * Get number of queued executions
     */
    public function getQueuedCount(): int
    {
        if ($this->storage === null) {
            return $this->localQueued;
        }

        $count = $this->storage->get($this->getKey('queued'));
        return is_numeric($count) ? max(0, (int) $count) : 0;
    }

    /**
     * Get available capacity
     */
    public function getAvailableCapacity(): int
    {
        return max(0, $this->maxConcurrent - $this->getActiveCount());
    }

    /**
     * Get bulkhead statistics
     *
     * @return array{
     *     name: string,
     *     max_concurrent: int,
     *     active_count: int,
     *     queued_count: int,
     *     available_capacity: int,
     *     queue_size: int,
     *     total_executions: int,
     *     total_rejections: int,
     *     total_queue_timeouts: int,
     *     utilization_percent: float
     * }
     */
    public function getStatistics(): array
    {
        $activeCount = $this->getActiveCount();

        return [
            'name' => $this->name,
            'max_concurrent' => $this->maxConcurrent,
            'active_count' => $activeCount,
            'queued_count' => $this->getQueuedCount(),
            'available_capacity' => $this->getAvailableCapacity(),
            'queue_size' => $this->queueSize,
            'total_executions' => $this->totalExecutions,
            'total_rejections' => $this->totalRejections,
            'total_queue_timeouts' => $this->totalQueueTimeouts,
            'utilization_percent' => ($activeCount / $this->maxConcurrent) * 100,
        ];
    }

    // ==================== PRIVATE METHODS ====================

    private function tryAcquire(): bool
    {
        if ($this->storage === null) {
            if ($this->localActive >= $this->maxConcurrent) {
                return false;
            }
            $this->localActive++;
            return true;
        }

        // Atomic increment with limit check
        // Use a Lua script for true atomicity in Redis
        $key = $this->getKey('active');
        $current = $this->getActiveCount();

        if ($current >= $this->maxConcurrent) {
            return false;
        }

        // Increment with TTL as safety net (auto-cleanup if process dies)
        $this->storage->increment($key, 1, 300); // 5 min TTL
        return true;
    }

    private function release(): void
    {
        if ($this->storage === null) {
            $this->localActive = max(0, $this->localActive - 1);
            return;
        }

        $key = $this->getKey('active');
        $current = $this->getActiveCount();

        if ($current > 0) {
            // Decrement (increment by -1)
            $this->storage->increment($key, -1, 300);
        }
    }

    private function executeWithQueue(callable $operation): mixed
    {
        // Increment queue count
        $this->incrementQueued();

        $startTime = microtime(true);
        $acquired = false;

        try {
            // Polling loop with backoff
            $pollInterval = 0.01; // Start at 10ms
            $maxPollInterval = 0.1; // Max 100ms

            while ((microtime(true) - $startTime) < $this->queueTimeout) {
                if ($this->tryAcquire()) {
                    $acquired = true;
                    break;
                }

                // Exponential backoff on poll interval
                usleep((int) ($pollInterval * 1_000_000));
                $pollInterval = min($pollInterval * 1.5, $maxPollInterval);
            }

            if (!$acquired) {
                $this->totalQueueTimeouts++;
                throw new BulkheadTimeoutException(
                    "Queue timeout for bulkhead '{$this->name}' after {$this->queueTimeout}s",
                    $this->name,
                    $this->queueTimeout
                );
            }

            $this->totalExecutions++;
            return $operation();

        } finally {
            $this->decrementQueued();

            if ($acquired) {
                $this->release();
            }
        }
    }

    private function incrementQueued(): void
    {
        if ($this->storage === null) {
            $this->localQueued++;
            return;
        }

        $this->storage->increment($this->getKey('queued'), 1, 300);
    }

    private function decrementQueued(): void
    {
        if ($this->storage === null) {
            $this->localQueued = max(0, $this->localQueued - 1);
            return;
        }

        $current = $this->getQueuedCount();
        if ($current > 0) {
            $this->storage->increment($this->getKey('queued'), -1, 300);
        }
    }

    private function getKey(string $suffix): string
    {
        return 'bulkhead:' . $this->name . ':' . $suffix;
    }
}
