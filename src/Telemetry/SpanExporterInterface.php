<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * Span Exporter Interface
 *
 * Defines the contract for exporting spans to tracing backends.
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
interface SpanExporterInterface
{
    /**
     * Export spans to the backend
     *
     * @param array<string, mixed> $exportData OTLP-formatted export data
     * @return bool True if export succeeded
     */
    public function export(array $exportData): bool;

    /**
     * Shutdown the exporter
     *
     * Called when the application shuts down.
     * Should flush any pending exports.
     */
    public function shutdown(): void;
}
