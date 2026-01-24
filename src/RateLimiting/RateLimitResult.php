<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\RateLimiting;

/**
 * Rate Limit Result
 *
 * Contains the result of a rate limit check with metadata for HTTP headers.
 *
 * HTTP HEADERS (RFC 6585 & draft-ietf-httpapi-ratelimit-headers):
 * - X-RateLimit-Limit: Maximum requests allowed
 * - X-RateLimit-Remaining: Remaining requests in window
 * - X-RateLimit-Reset: Unix timestamp when limit resets
 * - Retry-After: Seconds until retry is allowed (when blocked)
 *
 * @package Senza1dio\SecurityShield\RateLimiting
 */
final class RateLimitResult
{
    /**
     * @param bool $allowed Whether the request is allowed
     * @param int $remaining Remaining requests in current window
     * @param int $limit Maximum requests allowed in window
     * @param int $resetAt Unix timestamp when limit resets
     * @param int $retryAfter Seconds until retry allowed (0 if allowed)
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly int $remaining,
        public readonly int $limit,
        public readonly int $resetAt,
        public readonly int $retryAfter = 0
    ) {
    }

    /**
     * Get HTTP headers for rate limit response
     *
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        $headers = [
            'X-RateLimit-Limit' => (string) $this->limit,
            'X-RateLimit-Remaining' => (string) $this->remaining,
            'X-RateLimit-Reset' => (string) $this->resetAt,
        ];

        if (!$this->allowed && $this->retryAfter > 0) {
            $headers['Retry-After'] = (string) $this->retryAfter;
        }

        return $headers;
    }

    /**
     * Get RateLimit-Policy header value (draft spec)
     *
     * @param string $name Policy name
     * @return string
     */
    public function getPolicyHeader(string $name = 'default'): string
    {
        $windowSeconds = $this->resetAt - time();
        return "{$this->limit};w={$windowSeconds};name=\"{$name}\"";
    }

    /**
     * Check if request was blocked
     */
    public function isBlocked(): bool
    {
        return !$this->allowed;
    }

    /**
     * Get utilization percentage
     */
    public function getUtilization(): float
    {
        $used = $this->limit - $this->remaining;
        return ($used / $this->limit) * 100;
    }

    /**
     * Convert to array for logging/debugging
     *
     * @return array{
     *     allowed: bool,
     *     remaining: int,
     *     limit: int,
     *     reset_at: int,
     *     retry_after: int,
     *     utilization: float
     * }
     */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'remaining' => $this->remaining,
            'limit' => $this->limit,
            'reset_at' => $this->resetAt,
            'retry_after' => $this->retryAfter,
            'utilization' => $this->getUtilization(),
        ];
    }
}
