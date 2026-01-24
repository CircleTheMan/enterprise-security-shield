<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health\Checks;

use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Health\CheckResult;
use Senza1dio\SecurityShield\Health\HealthCheckInterface;

/**
 * Storage Interface Health Check
 *
 * Generic health check for any StorageInterface implementation.
 */
class StorageHealthCheck implements HealthCheckInterface
{
    private StorageInterface $storage;
    private string $testKey;
    private int $timeoutMs;

    /**
     * @param StorageInterface $storage Storage to check
     * @param string $testKey Key to use for test operations
     * @param int $timeoutMs Timeout threshold in milliseconds
     */
    public function __construct(
        StorageInterface $storage,
        string $testKey = '_health_check_test',
        int $timeoutMs = 1000
    ) {
        $this->storage = $storage;
        $this->testKey = $testKey;
        $this->timeoutMs = $timeoutMs;
    }

    public function check(): CheckResult
    {
        $startTime = microtime(true);

        try {
            // Test write
            $testValue = (string) time();
            $writeResult = $this->storage->set($this->testKey, $testValue, 60);

            if (!$writeResult) {
                return CheckResult::unhealthy('Storage write failed');
            }

            // Test read
            $readValue = $this->storage->get($this->testKey);

            if ($readValue !== $testValue) {
                return CheckResult::unhealthy('Storage read returned wrong value');
            }

            // Test delete
            $deleteResult = $this->storage->delete($this->testKey);

            if (!$deleteResult) {
                return CheckResult::degraded('Storage delete failed (non-critical)');
            }

            $duration = (microtime(true) - $startTime) * 1000;

            $metadata = [
                'operation_time_ms' => round($duration, 2),
            ];

            // Check if operation was slow
            if ($duration > $this->timeoutMs) {
                return CheckResult::degraded(
                    "Storage operations slow: {$duration}ms",
                    $metadata
                );
            }

            return CheckResult::healthy('All operations successful', $metadata);

        } catch (\Throwable $e) {
            return CheckResult::unhealthy('Storage check failed: ' . $e->getMessage());
        }
    }
}
