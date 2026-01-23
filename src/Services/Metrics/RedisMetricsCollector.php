<?php

namespace Senza1dio\SecurityShield\Services\Metrics;

use Senza1dio\SecurityShield\Contracts\MetricsCollectorInterface;

/**
 * Redis Metrics Collector
 *
 * High-performance metrics collection using Redis
 *
 * @package Senza1dio\SecurityShield\Services\Metrics
 */
class RedisMetricsCollector implements MetricsCollectorInterface
{
    private \Redis $redis;
    private string $keyPrefix;

    public function __construct(\Redis $redis, string $keyPrefix = 'security_metrics:')
    {
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;
    }

    public function increment(string $metric, int $value = 1): void
    {
        try {
            $this->redis->incrBy($this->keyPrefix . $metric, $value);
        } catch (\RedisException $e) {
            // Graceful degradation
        }
    }

    public function gauge(string $metric, float $value): void
    {
        try {
            $this->redis->set($this->keyPrefix . $metric, (string) $value);
        } catch (\RedisException $e) {
            // Graceful degradation
        }
    }

    public function histogram(string $metric, float $value): void
    {
        try {
            // Store in sorted set for percentile calculations
            $this->redis->zAdd($this->keyPrefix . 'histogram:' . $metric, $value, (string) microtime(true));
            // Keep only last 1000 values
            $this->redis->zRemRangeByRank($this->keyPrefix . 'histogram:' . $metric, 0, -1001);
        } catch (\RedisException $e) {
            // Graceful degradation
        }
    }

    public function timing(string $metric, float $milliseconds): void
    {
        $this->histogram($metric, $milliseconds);
    }

    public function get(string $metric): ?float
    {
        try {
            $value = $this->redis->get($this->keyPrefix . $metric);
            return ($value !== false && is_numeric($value)) ? (float) $value : null;
        } catch (\RedisException $e) {
            return null;
        }
    }

    public function getAll(): array
    {
        try {
            $keys = $this->redis->keys($this->keyPrefix . '*');
            $metrics = [];

            foreach ($keys as $key) {
                $metric = str_replace($this->keyPrefix, '', $key);
                $value = $this->redis->get($key);
                if ($value !== false && is_numeric($value)) {
                    $metrics[$metric] = (float) $value;
                }
            }

            return $metrics;
        } catch (\RedisException $e) {
            return [];
        }
    }
}
