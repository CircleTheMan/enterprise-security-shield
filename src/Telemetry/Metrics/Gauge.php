<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Metrics;

/**
 * Gauge Metric
 *
 * A point-in-time measurement.
 * Use for tracking things like temperature, memory usage, etc.
 *
 * @package Senza1dio\SecurityShield\Telemetry\Metrics
 */
class Gauge
{
    private string $name;
    private string $description;
    private string $unit;

    /** @var array<string, float> */
    private array $values = [];

    public function __construct(
        string $name,
        string $description = '',
        string $unit = ''
    ) {
        $this->name = $name;
        $this->description = $description;
        $this->unit = $unit;
    }

    /**
     * Set gauge value
     *
     * @param float $value Value to set
     * @param array<string, string> $labels Metric labels
     */
    public function set(float $value, array $labels = []): void
    {
        $key = $this->labelsToKey($labels);
        $this->values[$key] = $value;
    }

    /**
     * Get current value
     *
     * @param array<string, string> $labels Metric labels
     */
    public function getValue(array $labels = []): ?float
    {
        $key = $this->labelsToKey($labels);
        return $this->values[$key] ?? null;
    }

    /**
     * Get all values
     *
     * @return array<string, float>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * Reset gauge
     */
    public function reset(): void
    {
        $this->values = [];
    }

    /**
     * Export to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $dataPoints = [];

        foreach ($this->values as $labelKey => $value) {
            $dataPoints[] = [
                'attributes' => $this->keyToLabels($labelKey),
                'value' => $value,
                'time_unix_nano' => (int) (microtime(true) * 1_000_000_000),
            ];
        }

        return [
            'name' => $this->name,
            'description' => $this->description,
            'unit' => $this->unit,
            'gauge' => [
                'data_points' => $dataPoints,
            ],
        ];
    }

    /**
     * Export to Prometheus format
     */
    public function toPrometheusFormat(): string
    {
        $output = [];

        if ($this->description) {
            $output[] = "# HELP {$this->name} {$this->description}";
        }

        $output[] = "# TYPE {$this->name} gauge";

        foreach ($this->values as $labelKey => $value) {
            $labels = $this->formatPrometheusLabels($labelKey);
            $output[] = "{$this->name}{$labels} {$value}";
        }

        return implode("\n", $output);
    }

    /**
     * Convert labels to unique key
     *
     * @param array<string, string> $labels
     */
    private function labelsToKey(array $labels): string
    {
        if (empty($labels)) {
            return '';
        }

        ksort($labels);
        return json_encode($labels) ?: '';
    }

    /**
     * Convert key back to label array format
     *
     * @param string $key
     * @return array<int, array{key: string, value: array{string_value: string}}>
     */
    private function keyToLabels(string $key): array
    {
        if ($key === '') {
            return [];
        }

        $labels = json_decode($key, true) ?? [];
        $result = [];

        foreach ($labels as $name => $value) {
            $result[] = [
                'key' => $name,
                'value' => ['string_value' => $value],
            ];
        }

        return $result;
    }

    /**
     * Format labels for Prometheus
     */
    private function formatPrometheusLabels(string $key): string
    {
        if ($key === '') {
            return '';
        }

        $labels = json_decode($key, true) ?? [];

        if (empty($labels)) {
            return '';
        }

        $parts = [];

        foreach ($labels as $name => $value) {
            $escapedValue = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value);
            $parts[] = "{$name}=\"{$escapedValue}\"";
        }

        return '{' . implode(',', $parts) . '}';
    }
}
