<?php

namespace Senza1dio\SecurityShield\Storage;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Null Storage Backend - In-Memory (Development/Testing)
 *
 * Stores data in memory for testing and development.
 * Data is NOT persisted across requests.
 *
 * Use Cases:
 * - Unit testing
 * - Local development
 * - CI/CD pipelines
 * - Demos
 *
 * LIMITATIONS (By Design):
 * =========================
 * - NO persistence across requests
 * - NO concurrency simulation (race conditions not tested)
 * - NO window drift (time-based expiration simplified)
 * - NOT suitable for load testing or production
 *
 * TESTING SCOPE:
 * - Logic verification (correct flow)
 * - NOT performance or concurrency testing
 *
 * DO NOT use in production - data will be lost on script termination.
 */
class NullStorage implements StorageInterface
{
    /** @var array<string, array{score: int, expires_at: int}> */
    private array $scores = [];
    /** @var array<string, array{ip: string, reason: string, banned_at: int, expires_at: int}> */
    private array $bans = [];
    /** @var array<string, array{verified: bool, metadata: array<string, mixed>, expires_at: int}> */
    private array $botCache = [];
    /** @var array<string, array<int, array<string, mixed>>> */
    private array $events = [];
    /** @var array<string, array{count: int, expires_at: int}> */
    private array $rateLimits = [];
    /** @var array<string, array{value: mixed, expires_at: int}> Generic cache */
    private array $cache = [];

    /**
     * {@inheritDoc}
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $this->scores[$ip] = [
            'score' => $score,
            'expires_at' => time() + $ttl,
        ];
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getScore(string $ip): ?int
    {
        if (!isset($this->scores[$ip])) {
            return null;
        }

        // Check expiration
        if (time() > $this->scores[$ip]['expires_at']) {
            unset($this->scores[$ip]);
            return null;
        }

        return $this->scores[$ip]['score'];
    }

    /**
     * {@inheritDoc}
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $currentScore = $this->getScore($ip) ?? 0;
        $newScore = $currentScore + $points;
        $this->setScore($ip, $newScore, $ttl);
        return $newScore;
    }

    /**
     * {@inheritDoc}
     */
    public function isBanned(string $ip): bool
    {
        if (!isset($this->bans[$ip])) {
            return false;
        }

        // Check expiration
        if (time() > $this->bans[$ip]['expires_at']) {
            unset($this->bans[$ip]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     *
     * For in-memory storage, cache-only check is same as regular check
     */
    public function isIpBannedCached(string $ip): bool
    {
        return $this->isBanned($ip);
    }

    /**
     * {@inheritDoc}
     */
    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $this->bans[$ip] = [
            'ip' => $ip,
            'reason' => $reason,
            'banned_at' => time(),
            'expires_at' => time() + $duration,
        ];
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function unbanIP(string $ip): bool
    {
        if (isset($this->bans[$ip])) {
            unset($this->bans[$ip]);
            return true;
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $this->botCache[$ip] = [
            'verified' => $isLegitimate,
            'metadata' => $metadata,
            'cached_at' => time(),
            'expires_at' => time() + $ttl,
        ];
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getCachedBotVerification(string $ip): ?array
    {
        if (!isset($this->botCache[$ip])) {
            return null;
        }

        $cached = $this->botCache[$ip];

        // Check expiration
        if (time() > $cached['expires_at']) {
            unset($this->botCache[$ip]);
            return null;
        }

        return [
            'verified' => $cached['verified'],
            'metadata' => $cached['metadata'],
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        // Initialize type-specific event list with proper int keys
        $typeEvents = $this->events[$type] ?? [];

        $typeEvents[] = [
            'type' => $type,
            'ip' => $ip,
            'data' => $data,
            'timestamp' => time(),
        ];

        // Keep last 1000 events per type (memory limit)
        // Use array_slice instead of array_shift - O(1) vs O(n) reindexing
        if (count($typeEvents) > 1000) {
            $typeEvents = array_slice($typeEvents, -1000, null, false);
        }

        $this->events[$type] = $typeEvents;

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        /** @var array<int, array<string, mixed>> $events */
        $events = [];

        if ($type && isset($this->events[$type])) {
            // Get events for specific type
            $events = array_slice(array_reverse($this->events[$type]), 0, $limit);
        } else {
            // Get events from all types
            foreach ($this->events as $typeEvents) {
                $events = array_merge($events, $typeEvents);
            }

            // Sort by timestamp (newest first)
            usort($events, function($a, $b) {
                $aTimestamp = is_array($a) && isset($a['timestamp']) && is_int($a['timestamp']) ? $a['timestamp'] : 0;
                $bTimestamp = is_array($b) && isset($b['timestamp']) && is_int($b['timestamp']) ? $b['timestamp'] : 0;
                return $bTimestamp <=> $aTimestamp;
            });

            // Limit to requested count
            $events = array_slice($events, 0, $limit);
        }

        return array_values($events); // Ensure int keys
    }

    /**
     * {@inheritDoc}
     */
    public function incrementRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $now = time();
        $key = $ip . ':' . $action; // Separate counter per action

        // Initialize or get current rate limit data
        if (!isset($this->rateLimits[$key])) {
            $this->rateLimits[$key] = [
                'count' => 1,
                'expires_at' => $now + $window,
            ];
            return 1;
        }

        // Check if window expired - reset counter
        if ($now > $this->rateLimits[$key]['expires_at']) {
            $this->rateLimits[$key] = [
                'count' => 1,
                'expires_at' => $now + $window,
            ];
            return 1;
        }

        // Increment counter within window
        $this->rateLimits[$key]['count']++;
        return $this->rateLimits[$key]['count'];
    }

    /**
     * {@inheritDoc}
     *
     * NOTE: $window parameter not used in NullStorage
     *
     * REASON:
     * - Expiration already set by incrementRequestCount()
     * - NullStorage doesn't recalculate windows dynamically
     * - Window enforcement happens at increment time, not read time
     *
     * This is CORRECT for in-memory testing storage.
     * Race conditions and window drift are NOT simulated (intentional).
     */
    public function getRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $key = $ip . ':' . $action; // Separate counter per action

        if (!isset($this->rateLimits[$key])) {
            return 0;
        }

        // Check expiration
        if (time() > $this->rateLimits[$key]['expires_at']) {
            unset($this->rateLimits[$key]);
            return 0;
        }

        return $this->rateLimits[$key]['count'];
    }

    /**
     * {@inheritDoc}
     */
    public function clear(): bool
    {
        $this->scores = [];
        $this->bans = [];
        $this->botCache = [];
        $this->events = [];
        $this->rateLimits = [];
        $this->cache = [];
        return true;
    }

    /**
     * Get all data (for testing assertions)
     *
     * @return array<string, mixed>
     */
    public function getAllData(): array
    {
        return [
            'scores' => $this->scores,
            'bans' => $this->bans,
            'bot_cache' => $this->botCache,
            'events' => $this->events,
            'rate_limits' => $this->rateLimits,
            'cache' => $this->cache,
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $key): mixed
    {
        if (!isset($this->cache[$key])) {
            return null;
        }

        // Check expiration
        if (time() > $this->cache[$key]['expires_at']) {
            unset($this->cache[$key]);
            return null;
        }

        return $this->cache[$key]['value'];
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $key, mixed $value, int $ttl): bool
    {
        $this->cache[$key] = [
            'value' => $value,
            'expires_at' => time() + $ttl,
        ];
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function delete(string $key): bool
    {
        unset($this->cache[$key]);
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function exists(string $key): bool
    {
        if (!isset($this->cache[$key])) {
            return false;
        }

        // Check expiration
        if (time() > $this->cache[$key]['expires_at']) {
            unset($this->cache[$key]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function increment(string $key, int $delta, int $ttl): int
    {
        $current = $this->get($key);
        $currentValue = is_numeric($current) ? (int) $current : 0;
        $newValue = $currentValue + $delta;

        // Don't go below zero for counters
        if ($newValue < 0) {
            $newValue = 0;
        }

        $this->set($key, (string) $newValue, $ttl);

        return $newValue;
    }
}
