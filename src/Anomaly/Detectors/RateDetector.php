<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly\Detectors;

use Senza1dio\SecurityShield\Anomaly\Anomaly;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\DetectorInterface;
use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Rate Anomaly Detector
 *
 * Detects unusual request rates (spikes or drops) using sliding window analysis.
 *
 * IMPORTANT: Storage Considerations
 * ---------------------------------
 * This detector relies on StorageInterface for tracking rates across time windows.
 * Keys are stored with TTL = windowSize * (historyWindows + 1).
 *
 * - Redis/Memcached: Keys auto-expire via TTL, no cleanup needed
 * - Database Storage: Implement periodic cleanup of expired entries
 * - NullStorage: Not recommended - detector won't detect rate anomalies
 *
 * For NullStorage or in-memory storage without TTL support:
 * - Old keys accumulate and are never cleaned
 * - Consider calling cleanupOldEntries() periodically if using such storage
 *
 * USAGE:
 * ```php
 * $detector = new RateDetector($storage, 'request_rate');
 *
 * // Record requests
 * $detector->recordEvent('ip:192.168.1.1');
 *
 * // Check for anomalies
 * $anomalies = $detector->analyze([
 *     'identifier' => 'ip:192.168.1.1',
 *     'current_rate' => 150, // requests in current window
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Anomaly\Detectors
 */
class RateDetector implements DetectorInterface
{
    private StorageInterface $storage;
    private string $keyPrefix;

    private int $windowSize;
    private int $historyWindows;
    private float $spikeThreshold;
    private float $dropThreshold;

    /**
     * @param StorageInterface $storage Storage for rate tracking
     * @param string $keyPrefix Key prefix for storage
     * @param int $windowSize Window size in seconds
     * @param int $historyWindows Number of historical windows to track
     * @param float $spikeThreshold Multiplier for spike detection (e.g., 3.0 = 3x normal)
     * @param float $dropThreshold Multiplier for drop detection (e.g., 0.2 = 80% drop)
     */
    public function __construct(
        StorageInterface $storage,
        string $keyPrefix = 'rate_detector',
        int $windowSize = 60,
        int $historyWindows = 10,
        float $spikeThreshold = 3.0,
        float $dropThreshold = 0.2
    ) {
        $this->storage = $storage;
        $this->keyPrefix = $keyPrefix;
        $this->windowSize = $windowSize;
        $this->historyWindows = $historyWindows;
        $this->spikeThreshold = $spikeThreshold;
        $this->dropThreshold = $dropThreshold;
    }

    public function getName(): string
    {
        return 'rate';
    }

    /**
     * Record an event for rate tracking
     *
     * @param string $identifier Event identifier (e.g., IP, user ID)
     */
    public function recordEvent(string $identifier): void
    {
        $window = $this->getCurrentWindow();
        $key = $this->getKey($identifier, $window);

        // Increment current window count
        $current = (int) ($this->storage->get($key) ?? 0);
        $this->storage->set($key, (string) ($current + 1), $this->windowSize * ($this->historyWindows + 1));
    }

    /**
     * Get current rate for an identifier
     *
     * @param string $identifier Event identifier
     * @return int Current window count
     */
    public function getCurrentRate(string $identifier): int
    {
        $window = $this->getCurrentWindow();
        $key = $this->getKey($identifier, $window);

        return (int) ($this->storage->get($key) ?? 0);
    }

    public function analyze(array $data): array
    {
        $identifier = $data['identifier'] ?? '';
        $currentRate = $data['current_rate'] ?? $this->getCurrentRate($identifier);

        if ($identifier === '' || $currentRate === 0) {
            return [];
        }

        // Get historical rates
        $historicalRates = $this->getHistoricalRates($identifier);

        if (count($historicalRates) < 3) {
            // Not enough history
            return [];
        }

        // Calculate baseline
        $mean = array_sum($historicalRates) / count($historicalRates);
        $stddev = $this->calculateStddev($historicalRates, $mean);

        if ($mean === 0.0) {
            return [];
        }

        $anomalies = [];

        // Check for spike
        if ($currentRate > $mean * $this->spikeThreshold) {
            $ratio = $currentRate / $mean;
            $score = min(1.0, ($ratio - 1) / ($this->spikeThreshold * 2));

            $anomalies[] = new Anomaly(
                AnomalyType::RATE_ANOMALY,
                $score,
                "Request rate spike detected: {$currentRate} (normal: ~{$mean})",
                [
                    'identifier' => $identifier,
                    'current_rate' => $currentRate,
                    'baseline_mean' => round($mean, 2),
                    'baseline_stddev' => round($stddev, 2),
                    'ratio' => round($ratio, 2),
                    'type' => 'spike',
                ]
            );
        }

        // Check for drop
        if ($mean > 10 && $currentRate < $mean * $this->dropThreshold) {
            $ratio = $currentRate / $mean;
            $score = min(1.0, (1 - $ratio) / 0.8);

            $anomalies[] = new Anomaly(
                AnomalyType::RATE_ANOMALY,
                $score * 0.6, // Drops are usually less critical
                "Request rate drop detected: {$currentRate} (normal: ~{$mean})",
                [
                    'identifier' => $identifier,
                    'current_rate' => $currentRate,
                    'baseline_mean' => round($mean, 2),
                    'baseline_stddev' => round($stddev, 2),
                    'ratio' => round($ratio, 2),
                    'type' => 'drop',
                ]
            );
        }

        return $anomalies;
    }

    public function train(array $historicalData): void
    {
        // Rate detector learns from live data, no training needed
    }

    public function isReady(): bool
    {
        return true;
    }

    /**
     * Get historical rates for an identifier
     *
     * @param string $identifier
     * @return array<int, int>
     */
    private function getHistoricalRates(string $identifier): array
    {
        $currentWindow = $this->getCurrentWindow();
        $rates = [];

        for ($i = 1; $i <= $this->historyWindows; $i++) {
            $window = $currentWindow - $i;
            $key = $this->getKey($identifier, $window);
            $rate = (int) ($this->storage->get($key) ?? 0);

            if ($rate > 0) {
                $rates[] = $rate;
            }
        }

        return $rates;
    }

    /**
     * Get current window number
     */
    private function getCurrentWindow(): int
    {
        return (int) floor(time() / $this->windowSize);
    }

    /**
     * Get storage key
     */
    private function getKey(string $identifier, int $window): string
    {
        return "{$this->keyPrefix}:{$identifier}:{$window}";
    }

    /**
     * Calculate standard deviation
     *
     * @param array<int, int|float> $values
     * @param float $mean
     */
    private function calculateStddev(array $values, float $mean): float
    {
        if (count($values) < 2) {
            return 0.0;
        }

        $variance = 0.0;

        foreach ($values as $value) {
            $variance += ($value - $mean) ** 2;
        }

        return sqrt($variance / (count($values) - 1));
    }
}
