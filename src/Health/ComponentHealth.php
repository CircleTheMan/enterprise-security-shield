<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Health status of a single component.
 */
final class ComponentHealth
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly string $name,
        public readonly HealthStatus $status,
        public readonly ?string $message,
        public readonly float $duration, // milliseconds
        public readonly array $metadata,
        public readonly bool $critical,
    ) {
    }

    /**
     * Convert to array for JSON serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'status' => $this->status->value,
            'message' => $this->message,
            'duration_ms' => round($this->duration, 2),
            'critical' => $this->critical,
            'metadata' => $this->metadata,
        ];
    }
}
