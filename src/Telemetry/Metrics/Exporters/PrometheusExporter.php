<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Metrics\Exporters;

use Senza1dio\SecurityShield\Telemetry\Metrics\MetricExporterInterface;

/**
 * Prometheus Exporter
 *
 * Exposes metrics in Prometheus format via HTTP endpoint.
 *
 * USAGE:
 * ```php
 * $exporter = new PrometheusExporter('/tmp/prometheus_metrics.prom');
 *
 * // In your metrics endpoint handler:
 * header('Content-Type: text/plain; charset=utf-8');
 * echo file_get_contents('/tmp/prometheus_metrics.prom');
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry\Metrics\Exporters
 */
class PrometheusExporter implements MetricExporterInterface
{
    private string $filePath;

    /**
     * @param string $filePath Path to store Prometheus metrics file
     */
    public function __construct(string $filePath)
    {
        $this->filePath = $filePath;
        $this->ensureDirectory();
    }

    public function export(array $exportData): bool
    {
        $output = [];

        foreach ($exportData['scope_metrics'] ?? [] as $scopeMetric) {
            foreach ($scopeMetric['metrics'] ?? [] as $metric) {
                $prometheusFormat = $this->formatMetric($metric);

                if ($prometheusFormat !== '') {
                    $output[] = $prometheusFormat;
                }
            }
        }

        $content = implode("\n\n", $output) . "\n";

        // Atomic write: write to temp file then rename
        // This prevents Prometheus from reading partial/corrupted data
        $tempFile = $this->filePath . '.tmp.' . getmypid();

        $written = file_put_contents($tempFile, $content, LOCK_EX);

        if ($written === false) {
            @unlink($tempFile);
            return false;
        }

        // Atomic rename (on same filesystem)
        if (!rename($tempFile, $this->filePath)) {
            @unlink($tempFile);
            return false;
        }

        return true;
    }

    public function shutdown(): void
    {
        // Nothing to do
    }

    /**
     * Get the file path
     */
    public function getFilePath(): string
    {
        return $this->filePath;
    }

    /**
     * Format a single metric to Prometheus format
     *
     * @param array<string, mixed> $metric
     */
    private function formatMetric(array $metric): string
    {
        $name = $metric['name'] ?? '';
        $description = $metric['description'] ?? '';
        $output = [];

        if ($description) {
            $output[] = "# HELP {$name} {$description}";
        }

        // Counter or UpDownCounter (sum)
        if (isset($metric['sum'])) {
            $isMonotonic = $metric['sum']['is_monotonic'] ?? false;
            $type = $isMonotonic ? 'counter' : 'gauge';
            $output[] = "# TYPE {$name} {$type}";

            foreach ($metric['sum']['data_points'] ?? [] as $point) {
                $labels = $this->formatLabels($point['attributes'] ?? []);
                $value = $point['value'] ?? 0;
                $output[] = "{$name}{$labels} {$value}";
            }
        }

        // Gauge
        if (isset($metric['gauge'])) {
            $output[] = "# TYPE {$name} gauge";

            foreach ($metric['gauge']['data_points'] ?? [] as $point) {
                $labels = $this->formatLabels($point['attributes'] ?? []);
                $value = $point['value'] ?? 0;
                $output[] = "{$name}{$labels} {$value}";
            }
        }

        // Histogram
        if (isset($metric['histogram'])) {
            $output[] = "# TYPE {$name} histogram";

            foreach ($metric['histogram']['data_points'] ?? [] as $point) {
                $baseLabels = $point['attributes'] ?? [];
                $bounds = $point['explicit_bounds'] ?? [];
                $bucketCounts = $point['bucket_counts'] ?? [];

                // Output bucket lines
                $cumulativeCount = 0;

                for ($i = 0; $i < count($bounds); $i++) {
                    $cumulativeCount = $bucketCounts[$i] ?? 0;
                    $labels = $this->formatLabelsWithExtra($baseLabels, ['le' => (string) $bounds[$i]]);
                    $output[] = "{$name}_bucket{$labels} {$cumulativeCount}";
                }

                // +Inf bucket
                $labels = $this->formatLabelsWithExtra($baseLabels, ['le' => '+Inf']);
                $totalCount = $point['count'] ?? 0;
                $output[] = "{$name}_bucket{$labels} {$totalCount}";

                // Sum and count
                $labels = $this->formatLabels($baseLabels);
                $sum = $point['sum'] ?? 0;
                $output[] = "{$name}_sum{$labels} {$sum}";
                $output[] = "{$name}_count{$labels} {$totalCount}";
            }
        }

        return implode("\n", $output);
    }

    /**
     * Format labels for Prometheus
     *
     * @param array<int, array{key: string, value: array<string, mixed>}> $attributes
     */
    private function formatLabels(array $attributes): string
    {
        if (empty($attributes)) {
            return '';
        }

        $parts = [];

        foreach ($attributes as $attr) {
            $key = $attr['key'] ?? '';
            $value = $attr['value']['string_value'] ?? '';
            $escapedValue = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], (string) $value);
            $parts[] = "{$key}=\"{$escapedValue}\"";
        }

        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Format labels with additional labels
     *
     * @param array<int, array{key: string, value: array<string, mixed>}> $attributes
     * @param array<string, string> $extra
     */
    private function formatLabelsWithExtra(array $attributes, array $extra): string
    {
        $parts = [];

        foreach ($attributes as $attr) {
            $key = $attr['key'] ?? '';
            $value = $attr['value']['string_value'] ?? '';
            $escapedValue = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], (string) $value);
            $parts[] = "{$key}=\"{$escapedValue}\"";
        }

        foreach ($extra as $key => $value) {
            $escapedValue = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value);
            $parts[] = "{$key}=\"{$escapedValue}\"";
        }

        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Ensure directory exists
     */
    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);

        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}
