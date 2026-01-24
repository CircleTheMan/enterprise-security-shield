<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Metrics;

/**
 * OpenTelemetry-compatible Meter
 *
 * Creates and manages metrics for monitoring.
 *
 * USAGE:
 * ```php
 * $meter = new Meter('security-shield');
 * $meter->addExporter(new PrometheusExporter(9090));
 *
 * // Create counter
 * $requestCounter = $meter->createCounter('http_requests_total', 'Total HTTP requests');
 * $requestCounter->add(1, ['method' => 'POST', 'status' => '200']);
 *
 * // Create histogram
 * $latencyHistogram = $meter->createHistogram('request_latency_seconds', 'Request latency');
 * $latencyHistogram->record(0.125, ['endpoint' => '/api/check']);
 *
 * // Create gauge
 * $activeConnections = $meter->createGauge('active_connections', 'Active connections');
 * $activeConnections->set(42);
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry\Metrics
 */
class Meter
{
    private string $name;
    private string $version;

    /** @var array<string, Counter> */
    private array $counters = [];

    /** @var array<string, UpDownCounter> */
    private array $upDownCounters = [];

    /** @var array<string, Gauge> */
    private array $gauges = [];

    /** @var array<string, Histogram> */
    private array $histograms = [];

    /** @var array<int, MetricExporterInterface> */
    private array $exporters = [];

    /**
     * @param string $name Meter name (typically service name)
     * @param string $version Meter version
     */
    public function __construct(string $name, string $version = '1.0.0')
    {
        $this->name = $name;
        $this->version = $version;
    }

    // ==================== CONFIGURATION ====================

    /**
     * Add metric exporter
     */
    public function addExporter(MetricExporterInterface $exporter): self
    {
        $this->exporters[] = $exporter;
        return $this;
    }

    // ==================== METRIC CREATION ====================

    /**
     * Create a counter (monotonically increasing)
     *
     * @param string $name Metric name
     * @param string $description Metric description
     * @param string $unit Metric unit
     */
    public function createCounter(
        string $name,
        string $description = '',
        string $unit = ''
    ): Counter {
        if (!isset($this->counters[$name])) {
            $this->counters[$name] = new Counter($name, $description, $unit);
        }

        return $this->counters[$name];
    }

    /**
     * Create an up-down counter (can increase or decrease)
     *
     * @param string $name Metric name
     * @param string $description Metric description
     * @param string $unit Metric unit
     */
    public function createUpDownCounter(
        string $name,
        string $description = '',
        string $unit = ''
    ): UpDownCounter {
        if (!isset($this->upDownCounters[$name])) {
            $this->upDownCounters[$name] = new UpDownCounter($name, $description, $unit);
        }

        return $this->upDownCounters[$name];
    }

    /**
     * Create a gauge (point-in-time value)
     *
     * @param string $name Metric name
     * @param string $description Metric description
     * @param string $unit Metric unit
     */
    public function createGauge(
        string $name,
        string $description = '',
        string $unit = ''
    ): Gauge {
        if (!isset($this->gauges[$name])) {
            $this->gauges[$name] = new Gauge($name, $description, $unit);
        }

        return $this->gauges[$name];
    }

    /**
     * Create a histogram (distribution of values)
     *
     * @param string $name Metric name
     * @param string $description Metric description
     * @param string $unit Metric unit
     * @param array<int, float> $boundaries Histogram bucket boundaries
     */
    public function createHistogram(
        string $name,
        string $description = '',
        string $unit = '',
        array $boundaries = []
    ): Histogram {
        if (!isset($this->histograms[$name])) {
            $this->histograms[$name] = new Histogram($name, $description, $unit, $boundaries);
        }

        return $this->histograms[$name];
    }

    // ==================== EXPORT ====================

    /**
     * Export all metrics
     *
     * @return array<string, mixed> Export data
     */
    public function export(): array
    {
        $metrics = [];

        foreach ($this->counters as $counter) {
            $metrics[] = $counter->toArray();
        }

        foreach ($this->upDownCounters as $counter) {
            $metrics[] = $counter->toArray();
        }

        foreach ($this->gauges as $gauge) {
            $metrics[] = $gauge->toArray();
        }

        foreach ($this->histograms as $histogram) {
            $metrics[] = $histogram->toArray();
        }

        $exportData = [
            'resource' => [
                'attributes' => [
                    ['key' => 'service.name', 'value' => ['string_value' => $this->name]],
                    ['key' => 'service.version', 'value' => ['string_value' => $this->version]],
                ],
            ],
            'scope_metrics' => [
                [
                    'scope' => [
                        'name' => $this->name,
                        'version' => $this->version,
                    ],
                    'metrics' => $metrics,
                ],
            ],
        ];

        // Send to exporters
        foreach ($this->exporters as $exporter) {
            try {
                $exporter->export($exportData);
            } catch (\Throwable $e) {
                error_log("Metric export failed: " . $e->getMessage());
            }
        }

        return $exportData;
    }

    /**
     * Get all metrics in Prometheus format
     */
    public function toPrometheusFormat(): string
    {
        $output = [];

        foreach ($this->counters as $counter) {
            $output[] = $counter->toPrometheusFormat();
        }

        foreach ($this->upDownCounters as $counter) {
            $output[] = $counter->toPrometheusFormat();
        }

        foreach ($this->gauges as $gauge) {
            $output[] = $gauge->toPrometheusFormat();
        }

        foreach ($this->histograms as $histogram) {
            $output[] = $histogram->toPrometheusFormat();
        }

        return implode("\n", array_filter($output));
    }

    /**
     * Reset all metrics
     */
    public function reset(): void
    {
        foreach ($this->counters as $counter) {
            $counter->reset();
        }

        foreach ($this->upDownCounters as $counter) {
            $counter->reset();
        }

        foreach ($this->gauges as $gauge) {
            $gauge->reset();
        }

        foreach ($this->histograms as $histogram) {
            $histogram->reset();
        }
    }
}
