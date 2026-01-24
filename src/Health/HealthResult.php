<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Overall health check result
 */
final class HealthResult
{
    /**
     * @param HealthStatus $status Overall status
     * @param array<string, ComponentHealth> $components Component results
     * @param int $timestamp Check timestamp
     */
    public function __construct(
        public readonly HealthStatus $status,
        public readonly array $components,
        public readonly int $timestamp
    ) {
    }

    /**
     * Check if overall system is healthy
     */
    public function isHealthy(): bool
    {
        return $this->status === HealthStatus::HEALTHY;
    }

    /**
     * Check if system is available (healthy or degraded)
     */
    public function isAvailable(): bool
    {
        return $this->status->isAvailable();
    }

    /**
     * Get HTTP status code
     */
    public function getHttpStatusCode(): int
    {
        return $this->status->getHttpStatusCode();
    }

    /**
     * Get unhealthy components
     *
     * @return array<string, ComponentHealth>
     */
    public function getUnhealthyComponents(): array
    {
        return array_filter(
            $this->components,
            fn($c) => $c->status === HealthStatus::UNHEALTHY
        );
    }

    /**
     * Get degraded components
     *
     * @return array<string, ComponentHealth>
     */
    public function getDegradedComponents(): array
    {
        return array_filter(
            $this->components,
            fn($c) => $c->status === HealthStatus::DEGRADED
        );
    }

    /**
     * Get total check duration
     */
    public function getTotalDuration(): float
    {
        return array_sum(array_map(fn($c) => $c->duration, $this->components));
    }

    /**
     * Convert to array for JSON response
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status->value,
            'timestamp' => $this->timestamp,
            'duration_ms' => round($this->getTotalDuration(), 2),
            'components' => array_map(fn($c) => $c->toArray(), $this->components),
        ];
    }

    /**
     * Convert to JSON string
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT) ?: '{}';
    }

    /**
     * Convert to Prometheus format
     */
    public function toPrometheus(string $prefix = 'app'): string
    {
        $lines = [];

        // Overall health
        $healthy = $this->isHealthy() ? 1 : 0;
        $lines[] = "# HELP {$prefix}_health_status Overall health status (1=healthy, 0=unhealthy)";
        $lines[] = "# TYPE {$prefix}_health_status gauge";
        $lines[] = "{$prefix}_health_status {$healthy}";

        // Component health
        $lines[] = "# HELP {$prefix}_health_component Component health status";
        $lines[] = "# TYPE {$prefix}_health_component gauge";
        foreach ($this->components as $component) {
            $value = match ($component->status) {
                HealthStatus::HEALTHY => 1,
                HealthStatus::DEGRADED => 0.5,
                HealthStatus::UNHEALTHY => 0,
            };
            $escapedName = $this->escapePrometheusLabel($component->name);
            $lines[] = "{$prefix}_health_component{component=\"{$escapedName}\"} {$value}";
        }

        // Component duration
        $lines[] = "# HELP {$prefix}_health_check_duration_ms Health check duration in milliseconds";
        $lines[] = "# TYPE {$prefix}_health_check_duration_ms gauge";
        foreach ($this->components as $component) {
            $duration = round($component->duration, 2);
            $escapedName = $this->escapePrometheusLabel($component->name);
            $lines[] = "{$prefix}_health_check_duration_ms{component=\"{$escapedName}\"} {$duration}";
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * Escape label value for Prometheus format
     *
     * Per Prometheus spec, label values can contain any Unicode characters.
     * Backslash, double-quote, and line feed must be escaped as \\, \", and \n.
     */
    private function escapePrometheusLabel(string $value): string
    {
        return str_replace(
            ['\\', '"', "\n", "\r"],
            ['\\\\', '\\"', '\\n', '\\r'],
            $value
        );
    }
}
