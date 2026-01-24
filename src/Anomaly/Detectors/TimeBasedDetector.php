<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly\Detectors;

use Senza1dio\SecurityShield\Anomaly\Anomaly;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\DetectorInterface;

/**
 * Time-Based Anomaly Detector
 *
 * Detects unusual activity based on time patterns (off-hours, weekends, etc.).
 *
 * USAGE:
 * ```php
 * $detector = new TimeBasedDetector('Europe/Rome');
 *
 * // Train with normal activity hours
 * $detector->train([
 *     ['timestamp' => 1704110400], // Monday 9:00
 *     ['timestamp' => 1704114000], // Monday 10:00
 * ]);
 *
 * // Analyze request at unusual time
 * $anomalies = $detector->analyze([
 *     'timestamp' => 1704157200, // Monday 3:00 AM
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Anomaly\Detectors
 */
class TimeBasedDetector implements DetectorInterface
{
    private string $timezone;

    /** @var array<int, int> Hour distribution (0-23) */
    private array $hourDistribution = [];

    /** @var array<int, int> Day distribution (0=Sunday to 6=Saturday) */
    private array $dayDistribution = [];

    private int $totalSamples = 0;
    private bool $trained = false;

    private float $offHoursThreshold;

    /**
     * @param string $timezone Timezone for time analysis
     * @param float $offHoursThreshold Minimum ratio to be considered normal hours
     */
    public function __construct(
        string $timezone = 'UTC',
        float $offHoursThreshold = 0.02
    ) {
        $this->timezone = $timezone;
        $this->offHoursThreshold = $offHoursThreshold;
    }

    public function getName(): string
    {
        return 'time_based';
    }

    public function analyze(array $data): array
    {
        if (!$this->trained) {
            return [];
        }

        $timestamp = $data['timestamp'] ?? time();
        $dateTime = $this->createDateTime($timestamp);

        $hour = (int) $dateTime->format('G');
        $day = (int) $dateTime->format('w');

        $anomalies = [];

        // Check hour anomaly
        $hourRatio = $this->totalSamples > 0
            ? ($this->hourDistribution[$hour] ?? 0) / $this->totalSamples
            : 0;

        if ($hourRatio < $this->offHoursThreshold) {
            $score = $this->calculateTimeScore($hourRatio);

            $anomalies[] = new Anomaly(
                AnomalyType::TIME_ANOMALY,
                $score,
                "Activity at unusual hour: " . $dateTime->format('H:i'),
                [
                    'hour' => $hour,
                    'day_of_week' => $day,
                    'day_name' => $dateTime->format('l'),
                    'hour_ratio' => round($hourRatio, 4),
                    'timezone' => $this->timezone,
                    'local_time' => $dateTime->format('Y-m-d H:i:s'),
                ]
            );
        }

        // Check day anomaly
        $dayRatio = $this->totalSamples > 0
            ? ($this->dayDistribution[$day] ?? 0) / $this->totalSamples
            : 0;

        if ($dayRatio < $this->offHoursThreshold * 2) { // Less strict for days
            $score = $this->calculateTimeScore($dayRatio) * 0.7;

            if ($score > 0.3) {
                $anomalies[] = new Anomaly(
                    AnomalyType::TIME_ANOMALY,
                    $score,
                    "Activity on unusual day: " . $dateTime->format('l'),
                    [
                        'day_of_week' => $day,
                        'day_name' => $dateTime->format('l'),
                        'day_ratio' => round($dayRatio, 4),
                        'timezone' => $this->timezone,
                    ]
                );
            }
        }

        return $anomalies;
    }

    public function train(array $historicalData): void
    {
        $this->hourDistribution = array_fill(0, 24, 0);
        $this->dayDistribution = array_fill(0, 7, 0);
        $this->totalSamples = 0;

        foreach ($historicalData as $sample) {
            $timestamp = $sample['timestamp'] ?? null;

            if ($timestamp === null) {
                continue;
            }

            $dateTime = $this->createDateTime($timestamp);

            $hour = (int) $dateTime->format('G');
            $day = (int) $dateTime->format('w');

            $this->hourDistribution[$hour]++;
            $this->dayDistribution[$day]++;
            $this->totalSamples++;
        }

        $this->trained = $this->totalSamples >= 100;
    }

    public function isReady(): bool
    {
        return $this->trained;
    }

    /**
     * Set business hours manually
     *
     * @param int $startHour Start hour (0-23)
     * @param int $endHour End hour (0-23)
     * @param array<int> $workDays Working days (0=Sunday to 6=Saturday)
     * @param int $baseWeight Weight for business hours (higher = more normal)
     * @param int $offHoursWeight Weight for off-hours (lower = more anomalous)
     */
    public function setBusinessHours(
        int $startHour,
        int $endHour,
        array $workDays = [1, 2, 3, 4, 5],
        int $baseWeight = 100,
        int $offHoursWeight = 1
    ): void {
        // Initialize with off-hours weight (not zero, to avoid false positives)
        $this->hourDistribution = array_fill(0, 24, $offHoursWeight);
        $this->dayDistribution = array_fill(0, 7, $offHoursWeight);

        // Handle wrap-around hours (e.g., startHour=22, endHour=6)
        if ($startHour <= $endHour) {
            for ($h = $startHour; $h <= $endHour; $h++) {
                $this->hourDistribution[$h] = $baseWeight;
            }
        } else {
            // Wrap-around case
            for ($h = $startHour; $h <= 23; $h++) {
                $this->hourDistribution[$h] = $baseWeight;
            }
            for ($h = 0; $h <= $endHour; $h++) {
                $this->hourDistribution[$h] = $baseWeight;
            }
        }

        // Set work days
        foreach ($workDays as $day) {
            if ($day >= 0 && $day <= 6) {
                $this->dayDistribution[$day] = $baseWeight;
            }
        }

        // Calculate total samples based on weights
        $this->totalSamples = array_sum($this->hourDistribution);
        $this->trained = true;
    }

    /**
     * Get hour distribution
     *
     * @return array<int, int>
     */
    public function getHourDistribution(): array
    {
        return $this->hourDistribution;
    }

    /**
     * Get day distribution
     *
     * @return array<int, int>
     */
    public function getDayDistribution(): array
    {
        return $this->dayDistribution;
    }

    /**
     * Create DateTime from timestamp
     */
    private function createDateTime(int $timestamp): \DateTimeImmutable
    {
        return (new \DateTimeImmutable('@' . $timestamp))
            ->setTimezone(new \DateTimeZone($this->timezone));
    }

    /**
     * Calculate time anomaly score
     */
    private function calculateTimeScore(float $ratio): float
    {
        if ($ratio === 0.0) {
            return 0.8; // Never seen, but not necessarily critical
        }

        // Scale based on how rare
        $score = 1 - ($ratio / $this->offHoursThreshold);

        return max(0.0, min(1.0, $score * 0.7));
    }
}
