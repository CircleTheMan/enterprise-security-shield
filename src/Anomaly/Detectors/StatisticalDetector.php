<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly\Detectors;

use Senza1dio\SecurityShield\Anomaly\Anomaly;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\DetectorInterface;

/**
 * Statistical Anomaly Detector
 *
 * Detects anomalies using statistical methods (Z-score, IQR).
 *
 * USAGE:
 * ```php
 * $detector = new StatisticalDetector(['request_count', 'response_time']);
 *
 * // Train with historical data
 * $detector->train($historicalMetrics);
 *
 * // Analyze current data
 * $anomalies = $detector->analyze([
 *     'request_count' => 1500, // Normal: 100-200
 *     'response_time' => 2.5,  // Normal: 0.1-0.3
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Anomaly\Detectors
 */
class StatisticalDetector implements DetectorInterface
{
    /** @var array<string> */
    private array $metrics;

    /** @var array<string, array{mean: float, stddev: float, q1: float, q3: float, iqr: float}> */
    private array $baselines = [];

    private float $zScoreThreshold;
    private float $iqrMultiplier;
    private bool $trained = false;

    /**
     * @param array<string> $metrics Metrics to monitor
     * @param float $zScoreThreshold Z-score threshold for anomaly detection
     * @param float $iqrMultiplier IQR multiplier for outlier detection
     */
    public function __construct(
        array $metrics,
        float $zScoreThreshold = 3.0,
        float $iqrMultiplier = 1.5
    ) {
        $this->metrics = $metrics;
        $this->zScoreThreshold = $zScoreThreshold;
        $this->iqrMultiplier = $iqrMultiplier;
    }

    public function getName(): string
    {
        return 'statistical';
    }

    public function analyze(array $data): array
    {
        if (!$this->trained) {
            return [];
        }

        $anomalies = [];

        foreach ($this->metrics as $metric) {
            if (!isset($data[$metric]) || !isset($this->baselines[$metric])) {
                continue;
            }

            $value = (float) $data[$metric];
            $baseline = $this->baselines[$metric];

            // Calculate Z-score
            // When stddev is 0 (all values identical), any deviation is highly anomalous
            if (abs($baseline['stddev']) < PHP_FLOAT_EPSILON) {
                // If value equals mean, no anomaly; otherwise, treat as extreme anomaly
                $zScore = abs($value - $baseline['mean']) < PHP_FLOAT_EPSILON ? 0.0 : $this->zScoreThreshold * 3;
            } else {
                $zScore = ($value - $baseline['mean']) / $baseline['stddev'];
            }

            // Check IQR bounds
            $lowerBound = $baseline['q1'] - ($this->iqrMultiplier * $baseline['iqr']);
            $upperBound = $baseline['q3'] + ($this->iqrMultiplier * $baseline['iqr']);
            $isIqrOutlier = $value < $lowerBound || $value > $upperBound;

            // Determine if anomalous
            if (abs($zScore) > $this->zScoreThreshold || $isIqrOutlier) {
                $score = $this->calculateScore($zScore, $value, $baseline);
                $direction = $value > $baseline['mean'] ? 'above' : 'below';

                $anomalies[] = new Anomaly(
                    AnomalyType::STATISTICAL_ANOMALY,
                    $score,
                    "Metric '{$metric}' is {$direction} normal range (value: {$value}, mean: {$baseline['mean']})",
                    [
                        'metric' => $metric,
                        'value' => $value,
                        'mean' => $baseline['mean'],
                        'stddev' => $baseline['stddev'],
                        'z_score' => round($zScore, 2),
                        'lower_bound' => round($lowerBound, 2),
                        'upper_bound' => round($upperBound, 2),
                        'direction' => $direction,
                    ]
                );
            }
        }

        return $anomalies;
    }

    public function train(array $historicalData): void
    {
        if (empty($historicalData)) {
            return;
        }

        foreach ($this->metrics as $metric) {
            $values = array_filter(
                array_column($historicalData, $metric),
                fn($v) => $v !== null
            );

            if (count($values) < 2) {
                continue;
            }

            $values = array_values(array_map('floatval', $values));
            sort($values);

            $this->baselines[$metric] = [
                'mean' => $this->mean($values),
                'stddev' => $this->stddev($values),
                'q1' => $this->percentile($values, 25),
                'q3' => $this->percentile($values, 75),
                'iqr' => $this->percentile($values, 75) - $this->percentile($values, 25),
            ];
        }

        $this->trained = !empty($this->baselines);
    }

    public function isReady(): bool
    {
        return $this->trained;
    }

    /**
     * Get baseline for a metric
     *
     * @param string $metric
     * @return array{mean: float, stddev: float, q1: float, q3: float, iqr: float}|null
     */
    public function getBaseline(string $metric): ?array
    {
        return $this->baselines[$metric] ?? null;
    }

    /**
     * Set baseline manually (useful for testing or preset values)
     *
     * @param string $metric
     * @param float $mean
     * @param float $stddev
     */
    public function setBaseline(string $metric, float $mean, float $stddev): void
    {
        $this->baselines[$metric] = [
            'mean' => $mean,
            'stddev' => $stddev,
            'q1' => $mean - $stddev,
            'q3' => $mean + $stddev,
            'iqr' => 2 * $stddev,
        ];
        $this->trained = true;
    }

    /**
     * Calculate anomaly score based on deviation
     *
     * @param float $zScore Z-score of the value
     * @param float $value Current value
     * @param array{mean: float, stddev: float, q1: float, q3: float, iqr: float} $baseline
     */
    private function calculateScore(float $zScore, float $value, array $baseline): float
    {
        $absZ = abs($zScore);

        // Normalize Z-score to 0-1 range
        // Z-score of 3 = 0.4 (threshold)
        // Z-score of 6 = 0.7 (high)
        // Z-score of 10+ = 0.9+ (critical)
        $score = 1 - (1 / (1 + ($absZ / $this->zScoreThreshold) ** 2));

        return min(1.0, max(0.0, $score));
    }

    /**
     * Calculate mean of values
     *
     * @param array<int, float> $values
     */
    private function mean(array $values): float
    {
        if (empty($values)) {
            return 0.0;
        }

        return array_sum($values) / count($values);
    }

    /**
     * Calculate standard deviation
     *
     * @param array<int, float> $values
     */
    private function stddev(array $values): float
    {
        if (count($values) < 2) {
            return 0.0;
        }

        $mean = $this->mean($values);
        $variance = 0.0;

        foreach ($values as $value) {
            $variance += ($value - $mean) ** 2;
        }

        return sqrt($variance / (count($values) - 1));
    }

    /**
     * Calculate percentile
     *
     * @param array<int, float> $values Sorted values
     * @param int $percentile Percentile (0-100)
     */
    private function percentile(array $values, int $percentile): float
    {
        if (empty($values)) {
            return 0.0;
        }

        $index = ($percentile / 100) * (count($values) - 1);
        $lower = (int) floor($index);
        $upper = (int) ceil($index);

        if ($lower === $upper) {
            return $values[$lower];
        }

        $fraction = $index - $lower;

        return $values[$lower] + ($values[$upper] - $values[$lower]) * $fraction;
    }
}
