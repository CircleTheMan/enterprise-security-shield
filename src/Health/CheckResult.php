<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Result of a single health check
 */
final class CheckResult
{
    /**
     * @param HealthStatus $status Health status
     * @param string|null $message Optional message
     * @param array<string, mixed> $metadata Additional metadata
     */
    public function __construct(
        public readonly HealthStatus $status,
        public readonly ?string $message = null,
        public readonly array $metadata = []
    ) {
    }

    /**
     * Create a healthy result
     *
     * @param string|null $message Optional message
     * @param array<string, mixed> $metadata Additional metadata
     */
    public static function healthy(?string $message = null, array $metadata = []): self
    {
        return new self(HealthStatus::HEALTHY, $message, $metadata);
    }

    /**
     * Create a degraded result
     *
     * @param string $message Reason for degradation
     * @param array<string, mixed> $metadata Additional metadata
     */
    public static function degraded(string $message, array $metadata = []): self
    {
        return new self(HealthStatus::DEGRADED, $message, $metadata);
    }

    /**
     * Create an unhealthy result
     *
     * @param string $message Reason for failure
     * @param array<string, mixed> $metadata Additional metadata
     */
    public static function unhealthy(string $message, array $metadata = []): self
    {
        return new self(HealthStatus::UNHEALTHY, $message, $metadata);
    }

    /**
     * Check if healthy
     */
    public function isHealthy(): bool
    {
        return $this->status === HealthStatus::HEALTHY;
    }
}
