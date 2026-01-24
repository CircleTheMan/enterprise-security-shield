<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Metrics;

/**
 * Histogram Metric
 *
 * Tracks distribution of values in configurable buckets.
 * Use for latencies, request sizes, etc.
 *
 * @package Senza1dio\SecurityShield\Telemetry\Metrics
 */
class Histogram
{
    private string $name;
    private string $description;
    private string $unit;

    /** @var array<int, float> */
    private array $boundaries;

    /** @var array<string, array{buckets: array<int, int>, sum: float, count: int, min: float, max: float}> */
    private array $values = [];

    /**
     * Default HTTP latency boundaries in seconds
     */
    public const HTTP_LATENCY_BOUNDARIES = [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
    ];

    /**
     * Default size boundaries in bytes
     */
    public const SIZE_BOUNDARIES = [
        100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000
    ];

    /**
     * @param string $name Metric name
     * @param string $description Metric description
     * @param string $unit Metric unit
     * @param array<int, float> $boundaries Bucket boundaries
     */
    public function __construct(
        string $name,
        string $description = '',
        string $unit = '',
        array $boundaries = []
    ) {
        $this->name = $name;
        $this->description = $description;
        $this->unit = $unit;

        // Default to HTTP latency boundaries
        $this->boundaries = empty($boundaries) ? self::HTTP_LATENCY_BOUNDARIES : $boundaries;
        sort($this->boundaries);
    }

    /**
     * Record a value
     *
     * @param float $value Value to record
     * @param array<string, string> $labels Metric labels
     */
    public function record(float $value, array $labels = []): void
    {
        $key = $this->labelsToKey($labels);

        if (!isset($this->values[$key])) {
            $this->values[$key] = $this->createEmptyBuckets();
        }

        // Update buckets
        foreach ($this->boundaries as $i => $boundary) {
            if ($value <= $boundary) {
                $this->values[$key]['buckets'][$i]++;
            }
        }

        // +Inf bucket
        $this->values[$key]['buckets'][count($this->boundaries)]++;

        // Update sum and count
        $this->values[$key]['sum'] += $value;
        $this->values[$key]['count']++;

        // Update min/max
        if ($value < $this->values[$key]['min']) {
            $this->values[$key]['min'] = $value;
        }

        if ($value > $this->values[$key]['max']) {
            $this->values[$key]['max'] = $value;
        }
    }

    /**
     * Time a callable and record the duration
     *
     * @template T
     * @param callable(): T $operation Operation to time
     * @param array<string, string> $labels Metric labels
     * @return T
     */
    public function time(callable $operation, array $labels = []): mixed
    {
        $start = hrtime(true);

        try {
            return $operation();
        } finally {
            $duration = (hrtime(true) - $start) / 1_000_000_000;
            $this->record($duration, $labels);
        }
    }

    /**
     * Get statistics for labels
     *
     * @param array<string, string> $labels
     * @return array{count: int, sum: float, min: float, max: float, avg: float}|null
     */
    public function getStats(array $labels = []): ?array
    {
        $key = $this->labelsToKey($labels);

        if (!isset($this->values[$key])) {
            return null;
        }

        $data = $this->values[$key];

        return [
            'count' => $data['count'],
            'sum' => $data['sum'],
            'min' => $data['min'],
            'max' => $data['max'],
            'avg' => $data['count'] > 0 ? $data['sum'] / $data['count'] : 0,
        ];
    }

    /**
     * Get all values
     *
     * @return array<string, array{buckets: array<int, int>, sum: float, count: int, min: float, max: float}>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * Reset histogram
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

        foreach ($this->values as $labelKey => $data) {
            $bucketCounts = [];

            foreach ($data['buckets'] as $count) {
                $bucketCounts[] = $count;
            }

            $dataPoints[] = [
                'attributes' => $this->keyToLabels($labelKey),
                'start_time_unix_nano' => 0,
                'time_unix_nano' => (int) (microtime(true) * 1_000_000_000),
                'count' => $data['count'],
                'sum' => $data['sum'],
                'bucket_counts' => $bucketCounts,
                'explicit_bounds' => $this->boundaries,
                'min' => $data['min'],
                'max' => $data['max'],
            ];
        }

        return [
            'name' => $this->name,
            'description' => $this->description,
            'unit' => $this->unit,
            'histogram' => [
                'aggregation_temporality' => 'cumulative',
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

        $output[] = "# TYPE {$this->name} histogram";

        foreach ($this->values as $labelKey => $data) {
            $baseLabels = $labelKey !== '' ? json_decode($labelKey, true) : [];
            $cumulativeCount = 0;

            // Bucket lines
            foreach ($this->boundaries as $i => $boundary) {
                $cumulativeCount = $data['buckets'][$i];
                $labels = array_merge($baseLabels, ['le' => (string) $boundary]);
                $labelStr = $this->formatPrometheusLabelsArray($labels);
                $output[] = "{$this->name}_bucket{$labelStr} {$cumulativeCount}";
            }

            // +Inf bucket
            $labels = array_merge($baseLabels, ['le' => '+Inf']);
            $labelStr = $this->formatPrometheusLabelsArray($labels);
            $output[] = "{$this->name}_bucket{$labelStr} {$data['count']}";

            // Sum and count
            $baseLabelStr = $this->formatPrometheusLabels($labelKey);
            $output[] = "{$this->name}_sum{$baseLabelStr} {$data['sum']}";
            $output[] = "{$this->name}_count{$baseLabelStr} {$data['count']}";
        }

        return implode("\n", $output);
    }

    /**
     * Create empty bucket structure
     *
     * @return array{buckets: array<int, int>, sum: float, count: int, min: float, max: float}
     */
    private function createEmptyBuckets(): array
    {
        $buckets = [];

        // One bucket per boundary + one for +Inf
        for ($i = 0; $i <= count($this->boundaries); $i++) {
            $buckets[$i] = 0;
        }

        return [
            'buckets' => $buckets,
            'sum' => 0.0,
            'count' => 0,
            'min' => PHP_FLOAT_MAX,
            'max' => -PHP_FLOAT_MAX, // Use negative max, not PHP_FLOAT_MIN (smallest positive)
        ];
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

        return $this->formatPrometheusLabelsArray(json_decode($key, true) ?? []);
    }

    /**
     * Format label array for Prometheus
     *
     * @param array<string, string> $labels
     */
    private function formatPrometheusLabelsArray(array $labels): string
    {
        if (empty($labels)) {
            return '';
        }

        $parts = [];

        foreach ($labels as $name => $value) {
            $escapedValue = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], (string) $value);
            $parts[] = "{$name}=\"{$escapedValue}\"";
        }

        return '{' . implode(',', $parts) . '}';
    }
}
