<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Composite Anomaly Detector
 *
 * Combines multiple detection algorithms for comprehensive anomaly detection.
 *
 * FEATURES:
 * - Multiple detector support
 * - Score aggregation
 * - Correlation analysis
 * - Alert deduplication
 *
 * USAGE:
 * ```php
 * $detector = new AnomalyDetector();
 *
 * // Add detectors
 * $detector->addDetector(new StatisticalDetector(['request_count', 'latency']));
 * $detector->addDetector(new RateDetector($storage));
 * $detector->addDetector(new PatternDetector());
 * $detector->addDetector(new TimeBasedDetector('Europe/Rome'));
 *
 * // Train all detectors
 * $detector->train($historicalData);
 *
 * // Analyze request
 * $result = $detector->analyze([
 *     'request_count' => 500,
 *     'latency' => 2.5,
 *     'method' => 'POST',
 *     'path' => '/api/admin/delete',
 *     'timestamp' => time(),
 * ]);
 *
 * if ($result->hasAnomalies()) {
 *     foreach ($result->getAnomalies() as $anomaly) {
 *         $logger->warning('Anomaly detected', $anomaly->toArray());
 *     }
 * }
 * ```
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
class AnomalyDetector
{
    /** @var array<string, DetectorInterface> */
    private array $detectors = [];

    /** @var array<string, callable> */
    private array $alertHandlers = [];

    private AnomalySeverity $alertThreshold;
    private bool $deduplicateAlerts;
    private int $deduplicationWindow;

    /** @var array<string, float> */
    private array $recentAlerts = [];

    /**
     * @param AnomalySeverity $alertThreshold Minimum severity for alerts
     * @param bool $deduplicateAlerts Whether to deduplicate similar alerts
     * @param int $deduplicationWindow Deduplication window in seconds
     */
    public function __construct(
        AnomalySeverity $alertThreshold = AnomalySeverity::MEDIUM,
        bool $deduplicateAlerts = true,
        int $deduplicationWindow = 300
    ) {
        $this->alertThreshold = $alertThreshold;
        $this->deduplicateAlerts = $deduplicateAlerts;
        $this->deduplicationWindow = $deduplicationWindow;
    }

    /**
     * Add a detector
     *
     * @param DetectorInterface $detector
     * @param string|null $name Custom name (uses detector's name if null)
     */
    public function addDetector(DetectorInterface $detector, ?string $name = null): self
    {
        $name = $name ?? $detector->getName();
        $this->detectors[$name] = $detector;
        return $this;
    }

    /**
     * Remove a detector
     */
    public function removeDetector(string $name): self
    {
        unset($this->detectors[$name]);
        return $this;
    }

    /**
     * Add alert handler
     *
     * @param string $name Handler name
     * @param callable(Anomaly): void $handler Handler function
     */
    public function addAlertHandler(string $name, callable $handler): self
    {
        $this->alertHandlers[$name] = $handler;
        return $this;
    }

    /**
     * Train all detectors
     *
     * @param array<int, array<string, mixed>> $historicalData
     */
    public function train(array $historicalData): void
    {
        foreach ($this->detectors as $detector) {
            $detector->train($historicalData);
        }
    }

    /**
     * Analyze data for anomalies
     *
     * @param array<string, mixed> $data
     */
    public function analyze(array $data): AnomalyResult
    {
        $allAnomalies = [];

        foreach ($this->detectors as $name => $detector) {
            if (!$detector->isReady()) {
                continue;
            }

            $anomalies = $detector->analyze($data);

            foreach ($anomalies as $anomaly) {
                $anomaly->setMetadata('detector', $name);
                $allAnomalies[] = $anomaly;
            }
        }

        // Sort by score descending
        usort($allAnomalies, fn($a, $b) => $b->getScore() <=> $a->getScore());

        // Trigger alerts
        foreach ($allAnomalies as $anomaly) {
            if ($anomaly->isSeverityAtLeast($this->alertThreshold)) {
                $this->triggerAlert($anomaly);
            }
        }

        return new AnomalyResult($allAnomalies);
    }

    /**
     * Check if all detectors are ready
     */
    public function isReady(): bool
    {
        if (empty($this->detectors)) {
            return false;
        }

        foreach ($this->detectors as $detector) {
            if (!$detector->isReady()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get detector status
     *
     * @return array<string, bool>
     */
    public function getDetectorStatus(): array
    {
        $status = [];

        foreach ($this->detectors as $name => $detector) {
            $status[$name] = $detector->isReady();
        }

        return $status;
    }

    /**
     * Get detector by name
     */
    public function getDetector(string $name): ?DetectorInterface
    {
        return $this->detectors[$name] ?? null;
    }

    /**
     * Trigger alert for anomaly
     */
    private function triggerAlert(Anomaly $anomaly): void
    {
        // Check for deduplication
        if ($this->deduplicateAlerts) {
            $key = $this->getAlertKey($anomaly);
            $now = microtime(true);

            // Clean old alerts
            $this->recentAlerts = array_filter(
                $this->recentAlerts,
                fn($time) => ($now - $time) < $this->deduplicationWindow
            );

            // Skip if recently alerted
            if (isset($this->recentAlerts[$key])) {
                return;
            }

            $this->recentAlerts[$key] = $now;
        }

        // Call all handlers
        foreach ($this->alertHandlers as $handler) {
            try {
                $handler($anomaly);
            } catch (\Throwable $e) {
                // Don't let handler errors break detection
                error_log("Anomaly alert handler failed: " . $e->getMessage());
            }
        }
    }

    /**
     * Generate deduplication key for anomaly
     */
    private function getAlertKey(Anomaly $anomaly): string
    {
        return md5(
            $anomaly->getType()->value .
            ':' . $anomaly->getContextValue('identifier', '') .
            ':' . $anomaly->getContextValue('pattern_type', '')
        );
    }
}
