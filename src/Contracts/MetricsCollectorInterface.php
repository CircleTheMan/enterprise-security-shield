<?php

namespace Senza1dio\SecurityShield\Contracts;

/**
 * Metrics Collector Interface - In-Memory Oriented
 *
 * Collects security metrics for monitoring and analytics.
 *
 * DESIGN ORIENTATION:
 * - IN-MEMORY FIRST: get() and getAll() methods are designed for in-memory implementations
 * - Optimized for: debug, testing, custom dashboards
 * - Less optimal for: standard metrics systems (Prometheus, StatsD, Datadog)
 *
 * STANDARD METRICS SYSTEMS:
 * Prometheus, StatsD, Datadog typically do NOT have "get current value" methods:
 * - They aggregate metrics server-side
 * - Clients only SEND data (increment, gauge, histogram)
 * - No local state retrieval
 *
 * USE CASES:
 * - ✅ In-memory metrics for testing/debug
 * - ✅ Custom dashboard displaying current stats
 * - ✅ Real-time monitoring UI
 * - ⚠️ Prometheus/StatsD integration (get/getAll will return empty or dummy data)
 *
 * INTEGRATION WITH STANDARD SYSTEMS:
 * For Prometheus/StatsD/Datadog:
 * - Implement increment/gauge/histogram/timing normally (send to backend)
 * - Implement get()/getAll() as no-op or return dummy data
 * - Metrics are aggregated server-side, not client-side
 *
 * @package Senza1dio\SecurityShield\Contracts
 */
interface MetricsCollectorInterface
{
    /**
     * Increment a counter metric
     *
     * @param string $metric Metric name (e.g., 'attacks_blocked', 'requests_total')
     * @param int $value Increment value (default: 1)
     * @return void
     */
    public function increment(string $metric, int $value = 1): void;

    /**
     * Set a gauge metric (current value)
     *
     * @param string $metric Metric name (e.g., 'threat_score_avg', 'active_bans')
     * @param float $value Current value
     * @return void
     */
    public function gauge(string $metric, float $value): void;

    /**
     * Record a sample value (for percentile calculations)
     *
     * NOTE: Named "sample" instead of "histogram" because this stores raw values,
     * not pre-aggregated buckets like Prometheus histograms.
     *
     * @param string $metric Metric name (e.g., 'request_duration', 'threat_score')
     * @param float $value Value to record
     * @return void
     */
    public function sample(string $metric, float $value): void;

    /**
     * Record a histogram value (for distributions)
     *
     * @deprecated Use sample() instead. "histogram" is misleading for raw sample storage.
     * @param string $metric Metric name (e.g., 'request_duration', 'threat_score')
     * @param float $value Value to record
     * @return void
     */
    public function histogram(string $metric, float $value): void;

    /**
     * Record a timing metric
     *
     * @param string $metric Metric name (e.g., 'waf_processing_time')
     * @param float $milliseconds Duration in milliseconds
     * @return void
     */
    public function timing(string $metric, float $milliseconds): void;

    /**
     * Get current metric value
     *
     * @param string $metric Metric name
     * @return float|null Metric value or null if not found
     */
    public function get(string $metric): ?float;

    /**
     * Get all metrics
     *
     * @return array<string, float> All metrics
     */
    public function getAll(): array;
}
