<?php

namespace Senza1dio\SecurityShield\Contracts;

/**
 * Storage Interface - Framework-Agnostic Data Persistence
 *
 * Allows SecurityShield to work with any backend:
 * - Redis (recommended for production)
 * - Database (PostgreSQL, MySQL, SQLite)
 * - Memory (for testing)
 * - Custom implementations
 */
interface StorageInterface
{
    /**
     * Store IP threat score
     *
     * @param string $ip Client IP address
     * @param int $score Current threat score
     * @param int $ttl Time to live in seconds
     * @return bool Success
     */
    public function setScore(string $ip, int $score, int $ttl): bool;

    /**
     * Get IP threat score
     *
     * @param string $ip Client IP address
     * @return int|null Score or null if not found
     */
    public function getScore(string $ip): ?int;

    /**
     * Increment IP threat score
     *
     * CRITICAL: This operation MUST be atomic to prevent race conditions.
     *
     * ATOMICITY REQUIREMENT:
     * Multiple concurrent requests from same IP must correctly accumulate scores:
     * - Request A: incrementScore($ip, 10) → reads 0, writes 10
     * - Request B: incrementScore($ip, 15) → reads 0, writes 15 (WRONG - race condition)
     * - Expected: Final score = 25, Actual (non-atomic): 15
     *
     * IMPLEMENTATION GUIDANCE:
     * - Redis: Use INCRBY + GET in Lua script (atomic) ✅
     * - Database: Use UPDATE ... SET score = score + ? (atomic SQL) ✅
     * - In-memory: Use locks or atomic operations ✅
     * - WRONG: Read score, add points, write score (3 separate operations = race condition) ❌
     *
     * CONSEQUENCES OF NON-ATOMIC:
     * - Attacker sends 100 concurrent requests with 40 points each
     * - Expected: 4000 points → instant ban
     * - Non-atomic: Only 40-400 points → ban threshold NOT reached → attack succeeds
     *
     * @param string $ip Client IP address
     * @param int $points Points to add
     * @param int $ttl Time to live in seconds
     * @return int New score after increment
     */
    public function incrementScore(string $ip, int $points, int $ttl): int;

    /**
     * Check if IP is banned (may query database on cold cache)
     *
     * Use isIpBannedCached() for hot-path ban checks (avoids DB query).
     *
     * @param string $ip Client IP address
     * @return bool True if banned
     */
    public function isBanned(string $ip): bool;

    /**
     * Fast cache-only ban check (no database fallback)
     *
     * PERFORMANCE-CRITICAL: This method is called at the START of handle()
     * before ANY other operations (rate limiting, scoring, etc.).
     *
     * MUST be cache-only (Redis/Memory) - NO database queries allowed here.
     * Database fallback happens in isBanned() for cold cache scenarios.
     *
     * PURPOSE: Immediately block banned IPs without storage writes or scoring.
     * This prevents DoS storage amplification attacks where banned IPs continue
     * generating expensive storage operations.
     *
     * IMPLEMENTATION NOTES:
     * - Return false if cache unavailable (fail-open for availability)
     * - Cache should be warmed by isBanned() or banIP() calls
     * - TTL must match ban duration
     *
     * @param string $ip Client IP address
     * @return bool True if banned (cache hit), false if not banned or cache miss
     */
    public function isIpBannedCached(string $ip): bool;

    /**
     * Ban an IP address
     *
     * @param string $ip Client IP address
     * @param int $duration Ban duration in seconds
     * @param string $reason Ban reason
     * @return bool Success
     */
    public function banIP(string $ip, int $duration, string $reason): bool;

    /**
     * Unban an IP address
     *
     * @param string $ip Client IP address
     * @return bool Success
     */
    public function unbanIP(string $ip): bool;

    /**
     * Store bot verification result in cache
     *
     * @param string $ip Bot IP address
     * @param bool $isLegitimate Verification result
     * @param array<string, mixed> $metadata Bot metadata (user_agent, hostname, etc.)
     * @param int $ttl Cache TTL in seconds
     * @return bool Success
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool;

    /**
     * Get cached bot verification result
     *
     * @param string $ip Bot IP address
     * @return array<string, mixed>|null ['verified' => bool, 'metadata' => array] or null
     */
    public function getCachedBotVerification(string $ip): ?array;

    /**
     * Log security event (attack, honeypot access, etc.)
     *
     * @param string $type Event type (scan, honeypot, ban, etc.)
     * @param string $ip Client IP
     * @param array<string, mixed> $data Event data
     * @return bool Success
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool;

    /**
     * Get recent security events
     *
     * @param int $limit Number of events to retrieve
     * @param string|null $type Filter by event type
     * @return array<int, array<string, mixed>> Array of events
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array;

    /**
     * Increment request count for IP (rate limiting)
     *
     * Increments the request counter for a specific IP within a time window.
     * Used for rate limiting to prevent abuse and DDoS attacks.
     *
     * @param string $ip Client IP address
     * @param int $window Time window in seconds
     * @return int Current request count after increment
     */
    public function incrementRequestCount(string $ip, int $window): int;

    /**
     * Get request count for IP (rate limiting)
     *
     * Retrieves the current request count for a specific IP within a time window.
     * Returns 0 if no requests recorded or window expired.
     *
     * @param string $ip Client IP address
     * @param int $window Time window in seconds (not used in get, but kept for interface consistency)
     * @return int Current request count (0 if not found or expired)
     */
    public function getRequestCount(string $ip, int $window): int;

    /**
     * Clear all data (for testing)
     *
     * @return bool Success
     */
    public function clear(): bool;
}
