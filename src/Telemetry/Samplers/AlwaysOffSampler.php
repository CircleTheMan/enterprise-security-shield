<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Samplers;

use Senza1dio\SecurityShield\Telemetry\SamplerInterface;
use Senza1dio\SecurityShield\Telemetry\SpanKind;

/**
 * Always Off Sampler
 *
 * Never samples traces. Use in production when tracing is disabled.
 *
 * @package Senza1dio\SecurityShield\Telemetry\Samplers
 */
class AlwaysOffSampler implements SamplerInterface
{
    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        return false;
    }
}
