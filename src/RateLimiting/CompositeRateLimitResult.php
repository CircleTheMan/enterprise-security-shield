<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\RateLimiting;

/**
 * Composite Rate Limit Result
 *
 * Contains results from all rate limiters in a composite.
 */
final class CompositeRateLimitResult
{
    /**
     * @param bool $allowed Whether request is allowed by all limiters
     * @param int $remaining Minimum remaining across all limiters
     * @param int $resetAt Earliest reset time across all limiters
     * @param int $retryAfter Maximum retry-after across all limiters
     * @param array<string, RateLimitResult> $tierResults Individual results per tier
     * @param string|null $limitingTier Name of the most restrictive tier
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly int $remaining,
        public readonly int $resetAt,
        public readonly int $retryAfter,
        public readonly array $tierResults,
        public readonly ?string $limitingTier
    ) {
    }

    /**
     * Get result for a specific tier
     */
    public function getTierResult(string $name): ?RateLimitResult
    {
        return $this->tierResults[$name] ?? null;
    }

    /**
     * Get HTTP headers for response
     *
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        $headers = [
            'X-RateLimit-Remaining' => (string) $this->remaining,
            'X-RateLimit-Reset' => (string) $this->resetAt,
        ];

        if (!$this->allowed && $this->retryAfter > 0) {
            $headers['Retry-After'] = (string) $this->retryAfter;
        }

        // Add per-tier info
        foreach ($this->tierResults as $name => $result) {
            $headers["X-RateLimit-{$name}-Remaining"] = (string) $result->remaining;
            $headers["X-RateLimit-{$name}-Limit"] = (string) $result->limit;
        }

        return $headers;
    }

    /**
     * Get summary of all tiers
     *
     * @return array<string, array{remaining: int, limit: int, utilization: float}>
     */
    public function getTierSummary(): array
    {
        $summary = [];

        foreach ($this->tierResults as $name => $result) {
            $summary[$name] = [
                'remaining' => $result->remaining,
                'limit' => $result->limit,
                'utilization' => $result->getUtilization(),
            ];
        }

        return $summary;
    }

    /**
     * Check if request was blocked
     */
    public function isBlocked(): bool
    {
        return !$this->allowed;
    }
}
