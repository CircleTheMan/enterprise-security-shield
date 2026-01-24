<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Anomaly Detector Interface
 *
 * Contract for anomaly detection algorithms.
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
interface DetectorInterface
{
    /**
     * Get detector name
     */
    public function getName(): string;

    /**
     * Analyze data for anomalies
     *
     * @param array<string, mixed> $data Data to analyze
     * @return array<int, Anomaly> Detected anomalies
     */
    public function analyze(array $data): array;

    /**
     * Train the detector with historical data
     *
     * @param array<int, array<string, mixed>> $historicalData Training data
     */
    public function train(array $historicalData): void;

    /**
     * Check if detector is ready (trained)
     */
    public function isReady(): bool;
}
