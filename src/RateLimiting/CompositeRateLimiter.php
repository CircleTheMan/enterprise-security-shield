<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\RateLimiting;

/**
 * Composite Rate Limiter
 *
 * Combines multiple rate limiters for multi-tier rate limiting.
 * All limiters must pass for request to be allowed.
 *
 * USAGE:
 * ```php
 * // Common pattern: second, minute, hour limits
 * $limiter = new CompositeRateLimiter([
 *     RateLimiter::slidingWindow($storage, 10, 1),     // 10/second
 *     RateLimiter::slidingWindow($storage, 100, 60),   // 100/minute
 *     RateLimiter::slidingWindow($storage, 1000, 3600), // 1000/hour
 * ]);
 *
 * // Different limits for different operations
 * $limiter = new CompositeRateLimiter([
 *     'read' => RateLimiter::slidingWindow($storage, 100, 60),
 *     'write' => RateLimiter::slidingWindow($storage, 10, 60),
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\RateLimiting
 */
class CompositeRateLimiter
{
    /** @var array<string, RateLimiter> */
    private array $limiters = [];

    /**
     * @param array<string|int, RateLimiter> $limiters Named or indexed limiters
     */
    public function __construct(array $limiters = [])
    {
        foreach ($limiters as $name => $limiter) {
            $this->add(is_string($name) ? $name : 'tier_' . $name, $limiter);
        }
    }

    /**
     * Add a rate limiter to the composite
     *
     * @param string $name Unique name for this limiter
     * @param RateLimiter $limiter The rate limiter
     */
    public function add(string $name, RateLimiter $limiter): self
    {
        $this->limiters[$name] = $limiter;
        return $this;
    }

    /**
     * Attempt to consume tokens from all limiters
     *
     * Request is allowed only if ALL limiters allow it.
     * If any limiter blocks, tokens are NOT consumed from any.
     *
     * @param string $identifier Unique identifier
     * @param int $cost Token cost
     * @return CompositeRateLimitResult Combined result
     */
    public function attempt(string $identifier, int $cost = 1): CompositeRateLimitResult
    {
        // First pass: check all limiters without consuming
        $results = [];
        $allowed = true;

        foreach ($this->limiters as $name => $limiter) {
            $result = $limiter->attempt($identifier, 0); // Check only
            $results[$name] = $result;

            if ($result->remaining < $cost) {
                $allowed = false;
            }
        }

        // Second pass: consume tokens only if all allow
        if ($allowed && $cost > 0) {
            foreach ($this->limiters as $name => $limiter) {
                $results[$name] = $limiter->attempt($identifier, $cost);
            }
        }

        // Find the most restrictive limit
        $minRemaining = PHP_INT_MAX;
        $maxRetryAfter = 0;
        $earliestReset = PHP_INT_MAX;
        $limitingTier = null;

        foreach ($results as $name => $result) {
            if ($result->remaining < $minRemaining) {
                $minRemaining = $result->remaining;
                $limitingTier = $name;
            }
            if ($result->retryAfter > $maxRetryAfter) {
                $maxRetryAfter = $result->retryAfter;
            }
            if ($result->resetAt < $earliestReset) {
                $earliestReset = $result->resetAt;
            }
        }

        return new CompositeRateLimitResult(
            allowed: $allowed,
            remaining: $minRemaining === PHP_INT_MAX ? 0 : $minRemaining,
            resetAt: $earliestReset === PHP_INT_MAX ? time() : $earliestReset,
            retryAfter: $maxRetryAfter,
            tierResults: $results,
            limitingTier: $limitingTier
        );
    }

    /**
     * Check remaining tokens for all limiters
     *
     * @param string $identifier Unique identifier
     * @return array<string, int> Remaining tokens per limiter
     */
    public function remaining(string $identifier): array
    {
        $remaining = [];

        foreach ($this->limiters as $name => $limiter) {
            $remaining[$name] = $limiter->remaining($identifier);
        }

        return $remaining;
    }

    /**
     * Reset all limiters for an identifier
     *
     * @param string $identifier Unique identifier
     */
    public function reset(string $identifier): void
    {
        foreach ($this->limiters as $limiter) {
            $limiter->reset($identifier);
        }
    }

    /**
     * Get all limiter configurations
     *
     * @return array<string, array<string, mixed>>
     */
    public function getConfiguration(): array
    {
        $config = [];

        foreach ($this->limiters as $name => $limiter) {
            $config[$name] = $limiter->getConfiguration();
        }

        return $config;
    }
}
