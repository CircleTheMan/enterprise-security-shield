<?php

namespace Senza1dio\SecurityShield\Storage;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Redis Storage Backend - High Performance
 *
 * Recommended for production environments with high traffic.
 * Provides sub-millisecond read/write operations.
 *
 * Requirements:
 * - ext-redis PHP extension
 * - Redis server 5.0+ (6.0+ recommended)
 *
 * Features:
 * - Automatic key expiration (TTL)
 * - Atomic increment operations
 * - High concurrency support
 * - Persistence optional
 */
class RedisStorage implements StorageInterface
{
    private \Redis $redis;
    private string $keyPrefix;

    /**
     * @param \Redis $redis Connected Redis instance
     * @param string $keyPrefix Key prefix for namespacing (default: 'security_shield:')
     */
    public function __construct(\Redis $redis, string $keyPrefix = 'security_shield:')
    {
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Graceful degradation on Redis failure.
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        try {
            return $this->redis->setex($key, $ttl, (string) $score) !== false;
        } catch (\RedisException $e) {
            // Graceful degradation - return false but don't crash app
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Returns null on Redis failure (same as key not found).
     */
    public function getScore(string $ip): ?int
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        try {
            $score = $this->redis->get($key);

            if ($score === false || $score === null) {
                return null;
            }

            return is_numeric($score) ? (int) $score : null;
        } catch (\RedisException $e) {
            // Graceful degradation - treat as key not found
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * 
     * Uses Lua script for atomic INCRBY + EXPIRE operation.
     * Prevents TTL loss under high concurrency.
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $key = $this->keyPrefix . 'score:' . $ip;

        // Lua script: Atomic increment + conditional expire
        // Only sets TTL if key has no TTL (new key or expired)
        $lua = <<<'LUA'
local key = KEYS[1]
local points = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local newScore = redis.call('INCRBY', key, points)
if redis.call('TTL', key) < 0 then
    redis.call('EXPIRE', key, ttl)
end
return newScore
LUA;

        try {
            $result = $this->redis->eval($lua, [$key, $points, $ttl], 1);

            // Handle Redis return type (int|Redis|false)
            if (!is_int($result)) {
                return 0;
            }

            return $result;
        } catch (\RedisException $e) {
            // Graceful degradation on Redis failure
            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Returns false on Redis failure (fail-open for availability).
     */
    public function isBanned(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;

        try {
            $exists = $this->redis->exists($key);
            return is_int($exists) && $exists > 0;
        } catch (\RedisException $e) {
            // Graceful degradation - assume not banned (fail-open)
            // Alternative: return true (fail-closed for security)
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * PERFORMANCE-CRITICAL: Cache-only check (same as isBanned for Redis)
     * Redis storage doesn't have slow fallback, so both methods are identical.
     */
    public function isIpBannedCached(string $ip): bool
    {
        return $this->isBanned($ip);
    }

    /**
     * {@inheritDoc}
     *
     * RESILIENCE: Returns false on Redis failure (ban not applied).
     */
    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;
        $data = json_encode([
            'ip' => $ip,
            'reason' => $reason,
            'banned_at' => time(),
            'expires_at' => time() + $duration,
        ]);

        try {
            return $this->redis->setex($key, $duration, $data) !== false;
        } catch (\RedisException $e) {
            // Graceful degradation - ban not applied but app continues
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function unbanIP(string $ip): bool
    {
        $key = $this->keyPrefix . 'ban:' . $ip;
        $deleted = $this->redis->del($key);
        return is_int($deleted) && $deleted > 0;
    }

    /**
     * {@inheritDoc}
     * @param array<string, mixed> $metadata
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $key = $this->keyPrefix . 'bot:' . $ip;
        $data = json_encode([
            'verified' => $isLegitimate,
            'metadata' => $metadata,
            'cached_at' => time(),
        ]);

        return $this->redis->setex($key, $ttl, $data) !== false;
    }

    /**
     * {@inheritDoc}
     * @return array<string, mixed>|null
     */
    public function getCachedBotVerification(string $ip): ?array
    {
        $key = $this->keyPrefix . 'bot:' . $ip;
        $data = $this->redis->get($key);

        if ($data === false || !is_string($data)) {
            return null;
        }

        $decoded = json_decode($data, true);
        if (!is_array($decoded) || !isset($decoded['verified'])) {
            return null;
        }

        return [
            'verified' => $decoded['verified'],
            'metadata' => $decoded['metadata'] ?? [],
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        $key = $this->keyPrefix . 'events:' . $type;
        $event = json_encode([
            'type' => $type,
            'ip' => $ip,
            'data' => $data,
            'timestamp' => time(),
        ]);

        // Store in Redis list (LPUSH for newest first)
        // Keep last 10,000 events per type
        $this->redis->lPush($key, $event);
        $this->redis->lTrim($key, 0, 9999);

        // Set 30-day expiration on the list
        $this->redis->expire($key, 2592000);

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        $events = [];

        if ($type) {
            // Get events for specific type
            $key = $this->keyPrefix . 'events:' . $type;
            $rawEvents = $this->redis->lRange($key, 0, $limit - 1);

            foreach ($rawEvents as $eventJson) {
                if (!is_string($eventJson)) {
                    continue;
                }
                $event = json_decode($eventJson, true);
                if (is_array($event)) {
                    $events[] = $event;
                }
            }
        } else {
            // Get events from all types using SCAN (non-blocking)
            //  Replaced KEYS with SCAN to avoid Redis blocking
            $pattern = $this->keyPrefix . 'events:*';
            $keys = $this->scanKeys($pattern);

            foreach ($keys as $key) {
                $rawEvents = $this->redis->lRange($key, 0, $limit - 1);

                foreach ($rawEvents as $eventJson) {
                    if (!is_string($eventJson)) {
                        continue;
                    }
                    $event = json_decode($eventJson, true);
                    if (is_array($event)) {
                        $events[] = $event;
                    }
                }
            }

            // Sort by timestamp (newest first)
            usort($events, function($a, $b) {
                return ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0);
            });

            // Limit to requested count
            $events = array_slice($events, 0, $limit);
        }

        return $events;
    }

    /**
     * {@inheritDoc}
     *
     *  Uses Lua script for atomic INCR + EXPIRE.
     * RESILIENCE: Returns 1 on Redis failure (allows request).
     */
    public function incrementRequestCount(string $ip, int $window): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $ip;

        // Lua script: Atomic increment + conditional expire
        $lua = <<<'LUA'
local key = KEYS[1]
local window = tonumber(ARGV[1])
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end
return count
LUA;

        try {
            $result = $this->redis->eval($lua, [$key, $window], 1);

            // Handle Redis return type
            if (!is_int($result)) {
                return 1;
            }

            return $result;
        } catch (\RedisException $e) {
            // Graceful degradation - allow request
            return 1;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getRequestCount(string $ip, int $window): int
    {
        $key = $this->keyPrefix . 'rate_limit:' . $ip;
        $count = $this->redis->get($key);

        if ($count === false || !is_numeric($count)) {
            return 0;
        }

        return (int) $count;
    }

    /**
     * {@inheritDoc}
     *
     *  Uses SCAN instead of KEYS to avoid blocking Redis.
     */
    public function clear(): bool
    {
        $pattern = $this->keyPrefix . '*';
        $keys = $this->scanKeys($pattern);

        if (empty($keys)) {
            return true;
        }

        // Delete in batches of 1000 to avoid blocking Redis
        $batchSize = 1000;
        $batches = array_chunk($keys, $batchSize);
        $totalDeleted = 0;

        foreach ($batches as $batch) {
            $deleted = $this->redis->del($batch);
            $totalDeleted += is_int($deleted) ? $deleted : 0;
        }

        return $totalDeleted > 0;
    }

    /**
     * Scan Redis keys using cursor-based iteration (non-blocking)
     *
     * PERFORMANCE: Unlike KEYS command, SCAN doesn't block Redis.
     * Safe for production with millions of keys.
     *
     * @param string $pattern Key pattern (e.g., "security_shield:*")
     * @param int $count Hint for number of keys to return per iteration
     * @return array<int, string> Matching keys
     */
    private function scanKeys(string $pattern, int $count = 1000): array
    {
        $keys = [];
        $cursor = null;

        do {
            try {
                // SCAN returns [cursor, [keys]]
                $result = $this->redis->scan($cursor, $pattern, $count);

                if ($result === false) {
                    break;
                }

                // Redis extension returns [cursor, keys]
                if (is_array($result) && count($result) >= 2) {
                    $cursor = $result[0];
                    /** @var mixed $foundKeys */
                    $foundKeys = $result[1];
                    if (is_array($foundKeys)) {
                        $keys = array_merge($keys, $foundKeys);
                    }
                }
            } catch (\RedisException $e) {
                // Graceful degradation on Redis failure
                break;
            }
        } while ($cursor > 0);

        return $keys;
    }

    /**
     * Get Redis instance (for custom operations)
     *
     * @return \Redis
     */
    public function getRedis(): \Redis
    {
        return $this->redis;
    }

    /**
     * Get key prefix
     *
     * @return string
     */
    public function getKeyPrefix(): string
    {
        return $this->keyPrefix;
    }

    /**
     * Generic cache GET (for GeoIP, metrics, etc.)
     *
     * @param string $key Cache key
     * @return mixed|null Cached value or null
     */
    public function get(string $key)
    {
        try {
            $value = $this->redis->get($this->keyPrefix . $key);

            if ($value === false) {
                return null;
            }

            // SECURITY: Only JSON decode (NEVER unserialize - prevents PHP Object Injection)
            if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                $decoded = json_decode($value, true);
                return is_array($decoded) ? $decoded : $value;
            }

            return $value;
        } catch (\RedisException $e) {
            return null;
        }
    }

    /**
     * Generic cache SET (for GeoIP, metrics, etc.)
     *
     * @param string $key Cache key
     * @param mixed $value Value to cache
     * @param int $ttl TTL in seconds
     * @return bool Success
     */
    public function set(string $key, $value, int $ttl): bool
    {
        try {
            // Serialize arrays/objects
            if (is_array($value) || is_object($value)) {
                $value = json_encode($value);
            }

            // Ensure $value is string or fallback to empty
            if (!is_string($value)) {
                return false;
            }

            return $this->redis->setex($this->keyPrefix . $key, $ttl, $value) !== false;
        } catch (\RedisException $e) {
            return false;
        }
    }
}
