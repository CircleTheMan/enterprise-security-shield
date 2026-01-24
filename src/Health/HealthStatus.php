<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Health Status Enum
 */
enum HealthStatus: string
{
    case HEALTHY = 'healthy';
    case DEGRADED = 'degraded';
    case UNHEALTHY = 'unhealthy';

    /**
     * Get HTTP status code for this health status
     */
    public function getHttpStatusCode(): int
    {
        return match ($this) {
            self::HEALTHY => 200,
            self::DEGRADED => 200, // Still serving, just degraded
            self::UNHEALTHY => 503,
        };
    }

    /**
     * Check if status indicates service is available
     */
    public function isAvailable(): bool
    {
        return $this !== self::UNHEALTHY;
    }
}
