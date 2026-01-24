<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Anomaly Severity Levels
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
enum AnomalySeverity: string
{
    /**
     * Low severity - monitor but don't alert
     */
    case LOW = 'low';

    /**
     * Medium severity - log and potentially alert
     */
    case MEDIUM = 'medium';

    /**
     * High severity - immediate alert
     */
    case HIGH = 'high';

    /**
     * Critical severity - immediate action required
     */
    case CRITICAL = 'critical';

    /**
     * Get numeric severity score (1-4)
     */
    public function score(): int
    {
        return match ($this) {
            self::LOW => 1,
            self::MEDIUM => 2,
            self::HIGH => 3,
            self::CRITICAL => 4,
        };
    }

    /**
     * Create from score
     */
    public static function fromScore(float $score): self
    {
        return match (true) {
            $score >= 0.9 => self::CRITICAL,
            $score >= 0.7 => self::HIGH,
            $score >= 0.4 => self::MEDIUM,
            default => self::LOW,
        };
    }
}
