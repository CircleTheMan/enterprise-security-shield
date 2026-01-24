<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Samplers;

use Senza1dio\SecurityShield\Telemetry\SamplerInterface;
use Senza1dio\SecurityShield\Telemetry\SpanKind;

/**
 * Always On Sampler
 *
 * Samples all traces. Use in development or when complete tracing is needed.
 *
 * @package Senza1dio\SecurityShield\Telemetry\Samplers
 */
class AlwaysOnSampler implements SamplerInterface
{
    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        return true;
    }
}
