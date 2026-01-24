<?php

namespace Senza1dio\SecurityShield\Services\Metrics;

use Senza1dio\SecurityShield\Contracts\MetricsCollectorInterface;

/**
 * Redis Metrics Collector
 *
 * Metrics collection using Redis with proper production patterns.
 *
 * IMPORTANT LIMITATIONS:
 * - This is NOT a Prometheus exporter (no scraping endpoint)
 * - Samples are stored in sorted sets (not true histograms with buckets)
 * - getAll() uses SCAN (safe) but still O(N) on large keyspaces
 *
 * PRODUCTION RECOMMENDATIONS:
 * - Use dedicated Redis DB (SELECT N) for metrics
 * - Set reasonable TTL to prevent unbounded growth
 * - For high-traffic sites, consider dedicated metrics systems (Prometheus, DataDog)
 *
 * @package Senza1dio\SecurityShield\Services\Metrics
 */
class RedisMetricsCollector implements MetricsCollectorInterface
{
    private \Redis $redis;
    private string $keyPrefix;
    private int $defaultTTL;

    /**
     * @param \Redis $redis Redis connection
     * @param string $keyPrefix Key prefix for all metrics
     * @param int $defaultTTL Default TTL in seconds (default: 86400 = 24h)
     */
    public function __construct(\Redis $redis, string $keyPrefix = 'security_metrics:', int $defaultTTL = 86400)
    {
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;
        $this->defaultTTL = $defaultTTL;
    }

    /**
     * Increment a counter metric
     *
     * @param string $metric Metric name
     * @param int $value Value to add (default: 1)
     */
    public function increment(string $metric, int $value = 1): void
    {
        try {
            $key = $this->keyPrefix . $metric;
            $this->redis->incrBy($key, $value);
            // Set TTL only if key is new (doesn't reset on existing keys)
            $this->redis->expire($key, $this->defaultTTL);
        } catch (\RedisException $e) {
            // Graceful degradation - metrics are non-critical
        }
    }

    /**
     * Set a gauge metric (current value, e.g. active connections)
     *
     * @param string $metric Metric name
     * @param float $value Current value
     */
    public function gauge(string $metric, float $value): void
    {
        try {
            $key = $this->keyPrefix . $metric;
            $this->redis->set($key, (string) $value);
            $this->redis->expire($key, $this->defaultTTL);
        } catch (\RedisException $e) {
            // Graceful degradation
        }
    }

    /**
     * Record a sample value (for percentile calculations)
     *
     * NOTE: This is NOT a true histogram with buckets.
     * It stores raw samples in a sorted set, ordered by timestamp.
     * Use for latency/timing data where you need percentiles (p50, p95, p99).
     *
     * Storage: score = timestamp, member = "timestamp:value"
     * This allows time-based queries and deduplication.
     *
     * @param string $metric Metric name
     * @param float $value Sample value (e.g., latency in ms)
     */
    public function sample(string $metric, float $value): void
    {
        try {
            $key = $this->keyPrefix . 'samples:' . $metric;
            $timestamp = microtime(true);
            // Member = "timestamp:value" to allow duplicate values at different times
            $member = $timestamp . ':' . $value;

            $this->redis->zAdd($key, $timestamp, $member);
            // Keep only last 1000 samples (by removing oldest)
            $this->redis->zRemRangeByRank($key, 0, -1001);
            $this->redis->expire($key, $this->defaultTTL);
        } catch (\RedisException $e) {
            // Graceful degradation
        }
    }

    /**
     * Alias for sample() - records timing data
     *
     * @param string $metric Metric name
     * @param float $milliseconds Duration in milliseconds
     */
    public function timing(string $metric, float $milliseconds): void
    {
        $this->sample($metric, $milliseconds);
    }

    /**
     * @deprecated Use sample() instead. "histogram" was misleading.
     */
    public function histogram(string $metric, float $value): void
    {
        $this->sample($metric, $value);
    }

    /**
     * Get current value of a metric
     *
     * @param string $metric Metric name
     * @return float|null Value or null if not found
     */
    public function get(string $metric): ?float
    {
        try {
            $value = $this->redis->get($this->keyPrefix . $metric);
            return ($value !== false && is_numeric($value)) ? (float) $value : null;
        } catch (\RedisException $e) {
            return null;
        }
    }

    /**
     * Get percentile from samples
     *
     * @param string $metric Metric name
     * @param float $percentile Percentile (0.0-1.0, e.g., 0.95 for p95)
     * @return float|null Percentile value or null
     */
    public function getPercentile(string $metric, float $percentile): ?float
    {
        try {
            $key = $this->keyPrefix . 'samples:' . $metric;
            $samples = $this->redis->zRange($key, 0, -1);

            if (empty($samples)) {
                return null;
            }

            // Extract values from "timestamp:value" format
            $values = [];
            foreach ($samples as $sample) {
                $parts = explode(':', $sample, 2);
                if (isset($parts[1]) && is_numeric($parts[1])) {
                    $values[] = (float) $parts[1];
                }
            }

            if (empty($values)) {
                return null;
            }

            sort($values);
            $index = (int) floor($percentile * (count($values) - 1));
            return $values[$index];
        } catch (\RedisException $e) {
            return null;
        }
    }

    /**
     * Get all metrics (uses SCAN - safe for production)
     *
     * WARNING: Still O(N) on keyspace. For large datasets, use specific get() calls.
     *
     * @return array<string, float> Metric name => value
     */
    public function getAll(): array
    {
        try {
            $metrics = [];
            $cursor = null;
            $pattern = $this->keyPrefix . '*';
            $maxIterations = 1000; // Safety limit
            $iterations = 0;

            // Use SCAN instead of KEYS (non-blocking, cursor-based)
            do {
                $result = $this->redis->scan($cursor, $pattern, 100);

                if ($result === false) {
                    break;
                }

                if (is_array($result) && count($result) >= 2) {
                    $cursor = $result[0];
                    /** @var array<string> $keys */
                    $keys = $result[1];

                    foreach ($keys as $key) {
                        // Skip sample keys (sorted sets, not simple values)
                        if (str_contains($key, ':samples:')) {
                            continue;
                        }

                        $value = $this->redis->get($key);
                        if ($value !== false && is_numeric($value)) {
                            $metricName = str_replace($this->keyPrefix, '', $key);
                            $metrics[$metricName] = (float) $value;
                        }
                    }
                }

                $iterations++;
                if ($iterations >= $maxIterations) {
                    break;
                }
            } while ((int) $cursor > 0);

            return $metrics;
        } catch (\RedisException $e) {
            return [];
        }
    }

    /**
     * Set default TTL for all metrics
     *
     * @param int $seconds TTL in seconds
     * @return self
     */
    public function setDefaultTTL(int $seconds): self
    {
        $this->defaultTTL = $seconds;
        return $this;
    }
}
