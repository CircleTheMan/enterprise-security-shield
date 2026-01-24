<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Metrics;

/**
 * Metric Exporter Interface
 *
 * Defines the contract for exporting metrics to backends.
 *
 * @package Senza1dio\SecurityShield\Telemetry\Metrics
 */
interface MetricExporterInterface
{
    /**
     * Export metrics to the backend
     *
     * @param array<string, mixed> $exportData OTLP-formatted export data
     * @return bool True if export succeeded
     */
    public function export(array $exportData): bool;

    /**
     * Shutdown the exporter
     */
    public function shutdown(): void;
}
