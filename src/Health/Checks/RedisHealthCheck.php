<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health\Checks;

use Senza1dio\SecurityShield\Health\CheckResult;
use Senza1dio\SecurityShield\Health\HealthCheckInterface;

/**
 * Redis Health Check
 *
 * Verifies Redis connection and optionally checks memory usage.
 */
class RedisHealthCheck implements HealthCheckInterface
{
    private \Redis $redis;
    private ?float $memoryWarningThreshold;
    private ?float $memoryCriticalThreshold;

    /**
     * @param \Redis $redis Redis connection
     * @param float|null $memoryWarningThreshold Memory usage % for degraded (e.g., 80.0)
     * @param float|null $memoryCriticalThreshold Memory usage % for unhealthy (e.g., 95.0)
     */
    public function __construct(
        \Redis $redis,
        ?float $memoryWarningThreshold = 80.0,
        ?float $memoryCriticalThreshold = 95.0
    ) {
        $this->redis = $redis;
        $this->memoryWarningThreshold = $memoryWarningThreshold;
        $this->memoryCriticalThreshold = $memoryCriticalThreshold;
    }

    public function check(): CheckResult
    {
        try {
            // Basic connectivity check
            $pong = $this->redis->ping();

            if ($pong !== true && $pong !== '+PONG') {
                return CheckResult::unhealthy('Redis PING failed');
            }

            // Get server info
            $info = $this->redis->info();

            if (!is_array($info)) {
                return CheckResult::healthy('Connected', ['ping' => 'OK']);
            }

            $metadata = [
                'version' => $info['redis_version'] ?? 'unknown',
                'uptime_seconds' => $info['uptime_in_seconds'] ?? 0,
                'connected_clients' => $info['connected_clients'] ?? 0,
                'used_memory_human' => $info['used_memory_human'] ?? 'unknown',
            ];

            // Check memory usage
            if (isset($info['used_memory'], $info['maxmemory']) && $info['maxmemory'] > 0) {
                $memoryUsage = ($info['used_memory'] / $info['maxmemory']) * 100;
                $metadata['memory_usage_percent'] = round($memoryUsage, 2);

                if ($this->memoryCriticalThreshold !== null && $memoryUsage >= $this->memoryCriticalThreshold) {
                    return CheckResult::unhealthy(
                        "Memory usage critical: {$memoryUsage}%",
                        $metadata
                    );
                }

                if ($this->memoryWarningThreshold !== null && $memoryUsage >= $this->memoryWarningThreshold) {
                    return CheckResult::degraded(
                        "Memory usage high: {$memoryUsage}%",
                        $metadata
                    );
                }
            }

            return CheckResult::healthy('Connected', $metadata);

        } catch (\RedisException $e) {
            return CheckResult::unhealthy('Redis connection failed: ' . $e->getMessage());
        } catch (\Throwable $e) {
            return CheckResult::unhealthy('Redis check failed: ' . $e->getMessage());
        }
    }
}
