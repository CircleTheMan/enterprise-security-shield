<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Anomaly Detection Result
 *
 * Contains all anomalies detected in a single analysis run.
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
class AnomalyResult
{
    /** @var array<int, Anomaly> */
    private array $anomalies;

    private float $timestamp;

    /**
     * @param array<int, Anomaly> $anomalies Detected anomalies
     */
    public function __construct(array $anomalies = [])
    {
        $this->anomalies = $anomalies;
        $this->timestamp = microtime(true);
    }

    /**
     * Check if any anomalies were detected
     */
    public function hasAnomalies(): bool
    {
        return !empty($this->anomalies);
    }

    /**
     * Get all anomalies
     *
     * @return array<int, Anomaly>
     */
    public function getAnomalies(): array
    {
        return $this->anomalies;
    }

    /**
     * Get anomaly count
     */
    public function count(): int
    {
        return count($this->anomalies);
    }

    /**
     * Get highest severity anomaly
     */
    public function getHighestSeverity(): ?AnomalySeverity
    {
        if (empty($this->anomalies)) {
            return null;
        }

        $highest = null;

        foreach ($this->anomalies as $anomaly) {
            if ($highest === null || $anomaly->getSeverity()->score() > $highest->score()) {
                $highest = $anomaly->getSeverity();
            }
        }

        return $highest;
    }

    /**
     * Get highest score
     */
    public function getHighestScore(): float
    {
        if (empty($this->anomalies)) {
            return 0.0;
        }

        return max(array_map(fn($a) => $a->getScore(), $this->anomalies));
    }

    /**
     * Get anomalies by type
     *
     * @param AnomalyType $type
     * @return array<int, Anomaly>
     */
    public function getByType(AnomalyType $type): array
    {
        return array_values(array_filter(
            $this->anomalies,
            fn($a) => $a->getType() === $type
        ));
    }

    /**
     * Get anomalies by minimum severity
     *
     * @param AnomalySeverity $minSeverity
     * @return array<int, Anomaly>
     */
    public function getBySeverity(AnomalySeverity $minSeverity): array
    {
        return array_values(array_filter(
            $this->anomalies,
            fn($a) => $a->isSeverityAtLeast($minSeverity)
        ));
    }

    /**
     * Get anomalies by minimum score
     *
     * @param float $minScore
     * @return array<int, Anomaly>
     */
    public function getByScore(float $minScore): array
    {
        return array_values(array_filter(
            $this->anomalies,
            fn($a) => $a->getScore() >= $minScore
        ));
    }

    /**
     * Get critical anomalies
     *
     * @return array<int, Anomaly>
     */
    public function getCritical(): array
    {
        return $this->getBySeverity(AnomalySeverity::CRITICAL);
    }

    /**
     * Get high-severity anomalies
     *
     * @return array<int, Anomaly>
     */
    public function getHigh(): array
    {
        return $this->getBySeverity(AnomalySeverity::HIGH);
    }

    /**
     * Check if result contains critical anomalies
     */
    public function hasCritical(): bool
    {
        return !empty($this->getCritical());
    }

    /**
     * Check if result contains high-severity anomalies
     */
    public function hasHigh(): bool
    {
        return !empty($this->getHigh());
    }

    /**
     * Get timestamp
     */
    public function getTimestamp(): float
    {
        return $this->timestamp;
    }

    /**
     * Get summary statistics
     *
     * @return array{total: int, by_severity: array<string, int>, by_type: array<string, int>, highest_score: float}
     */
    public function getSummary(): array
    {
        $bySeverity = [];
        $byType = [];

        foreach ($this->anomalies as $anomaly) {
            $severity = $anomaly->getSeverity()->value;
            $type = $anomaly->getType()->value;

            $bySeverity[$severity] = ($bySeverity[$severity] ?? 0) + 1;
            $byType[$type] = ($byType[$type] ?? 0) + 1;
        }

        return [
            'total' => count($this->anomalies),
            'by_severity' => $bySeverity,
            'by_type' => $byType,
            'highest_score' => $this->getHighestScore(),
        ];
    }

    /**
     * Export to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'timestamp' => $this->timestamp,
            'has_anomalies' => $this->hasAnomalies(),
            'count' => $this->count(),
            'summary' => $this->getSummary(),
            'anomalies' => array_map(fn($a) => $a->toArray(), $this->anomalies),
        ];
    }

    /**
     * Export to JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR);
    }
}
