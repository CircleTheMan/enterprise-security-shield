<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Samplers;

use Senza1dio\SecurityShield\Telemetry\SamplerInterface;
use Senza1dio\SecurityShield\Telemetry\SpanKind;

/**
 * Ratio Based Sampler
 *
 * Samples traces based on a configurable ratio (0.0 to 1.0).
 *
 * USAGE:
 * ```php
 * // Sample 10% of traces
 * $sampler = new RatioBasedSampler(0.1);
 *
 * // Sample 50% of traces
 * $sampler = new RatioBasedSampler(0.5);
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry\Samplers
 */
class RatioBasedSampler implements SamplerInterface
{
    private float $ratio;
    private int $threshold;

    /**
     * @param float $ratio Sampling ratio (0.0 to 1.0)
     */
    public function __construct(float $ratio)
    {
        if ($ratio < 0.0 || $ratio > 1.0) {
            throw new \InvalidArgumentException('Ratio must be between 0.0 and 1.0');
        }

        $this->ratio = $ratio;
        $this->threshold = (int) ($ratio * PHP_INT_MAX);
    }

    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        if ($this->ratio === 0.0) {
            return false;
        }

        if ($this->ratio === 1.0) {
            return true;
        }

        return mt_rand(0, PHP_INT_MAX) < $this->threshold;
    }

    /**
     * Get configured ratio
     */
    public function getRatio(): float
    {
        return $this->ratio;
    }
}
