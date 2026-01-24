<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Samplers;

use Senza1dio\SecurityShield\Telemetry\SamplerInterface;
use Senza1dio\SecurityShield\Telemetry\SpanKind;

/**
 * Rule Based Sampler
 *
 * Samples traces based on configurable rules.
 * Rules are evaluated in order; first match wins.
 *
 * USAGE:
 * ```php
 * $sampler = new RuleBasedSampler(0.1); // 10% default
 *
 * // Always sample error spans
 * $sampler->addRule(
 *     fn($name, $kind, $attrs) => isset($attrs['error']),
 *     1.0
 * );
 *
 * // Sample 50% of security spans
 * $sampler->addRule(
 *     fn($name, $kind, $attrs) => str_starts_with($name, 'security.'),
 *     0.5
 * );
 *
 * // Never sample health checks
 * $sampler->addRule(
 *     fn($name, $kind, $attrs) => $name === 'health.check',
 *     0.0
 * );
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry\Samplers
 */
class RuleBasedSampler implements SamplerInterface
{
    private float $defaultRatio;

    /** @var array<int, array{matcher: callable, ratio: float}> */
    private array $rules = [];

    /**
     * @param float $defaultRatio Default sampling ratio if no rules match
     */
    public function __construct(float $defaultRatio = 1.0)
    {
        if ($defaultRatio < 0.0 || $defaultRatio > 1.0) {
            throw new \InvalidArgumentException('Ratio must be between 0.0 and 1.0');
        }

        $this->defaultRatio = $defaultRatio;
    }

    /**
     * Add a sampling rule
     *
     * @param callable(string, SpanKind, array<string, mixed>): bool $matcher Rule matcher
     * @param float $ratio Sampling ratio if rule matches (0.0 to 1.0)
     */
    public function addRule(callable $matcher, float $ratio): self
    {
        if ($ratio < 0.0 || $ratio > 1.0) {
            throw new \InvalidArgumentException('Ratio must be between 0.0 and 1.0');
        }

        $this->rules[] = [
            'matcher' => $matcher,
            'ratio' => $ratio,
        ];

        return $this;
    }

    /**
     * Add rule to always sample spans matching pattern
     *
     * @param string $namePattern Span name pattern (supports * wildcard)
     */
    public function alwaysSample(string $namePattern): self
    {
        return $this->addRule(
            fn($name) => $this->matchesPattern($name, $namePattern),
            1.0
        );
    }

    /**
     * Add rule to never sample spans matching pattern
     *
     * @param string $namePattern Span name pattern (supports * wildcard)
     */
    public function neverSample(string $namePattern): self
    {
        return $this->addRule(
            fn($name) => $this->matchesPattern($name, $namePattern),
            0.0
        );
    }

    /**
     * Add rule to sample spans with specific ratio by pattern
     *
     * @param string $namePattern Span name pattern (supports * wildcard)
     * @param float $ratio Sampling ratio
     */
    public function sampleWithRatio(string $namePattern, float $ratio): self
    {
        return $this->addRule(
            fn($name) => $this->matchesPattern($name, $namePattern),
            $ratio
        );
    }

    public function shouldSample(string $spanName, SpanKind $spanKind, array $attributes): bool
    {
        // Find matching rule
        $ratio = $this->defaultRatio;

        foreach ($this->rules as $rule) {
            if (($rule['matcher'])($spanName, $spanKind, $attributes)) {
                $ratio = $rule['ratio'];
                break;
            }
        }

        // Apply ratio
        if ($ratio === 0.0) {
            return false;
        }

        if ($ratio === 1.0) {
            return true;
        }

        return (mt_rand() / mt_getrandmax()) < $ratio;
    }

    /**
     * Match span name against pattern
     *
     * @param string $name Span name
     * @param string $pattern Pattern with optional * wildcards
     */
    private function matchesPattern(string $name, string $pattern): bool
    {
        // Convert pattern to regex
        $regex = '/^' . str_replace(
            ['\\*', '\\?'],
            ['.*', '.'],
            preg_quote($pattern, '/')
        ) . '$/';

        return (bool) preg_match($regex, $name);
    }
}
