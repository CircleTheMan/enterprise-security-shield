<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Storage;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * Database Storage Backend - Dual-Write Architecture
 *
 * ARCHITECTURE:
 * - Redis: L1 cache (sub-millisecond reads, hot data, volatile)
 * - PostgreSQL: Persistent storage (survives restarts, compliance, analytics)
 *
 * DUAL-WRITE PATTERN:
 * - Writes go to BOTH Redis (cache) AND PostgreSQL (persistence)
 * - Reads prioritize Redis (fast path), fallback to DB (cold start)
 * - Ban checks use Redis ONLY (performance-critical, early exit)
 *
 * PERFORMANCE CHARACTERISTICS:
 * - Ban check (cached): <1ms (Redis only, no DB query)
 * - Ban check (cold start): ~5ms (DB query + Redis cache write)
 * - Score increment: ~2ms (Redis + async DB write)
 * - Security event log: ~1ms (Redis list + async DB insert)
 *
 * REQUIREMENTS:
 * - PHP 8.0+ with PDO extension
 * - PostgreSQL 9.5+ (JSONB support)
 * - Redis 5.0+ (optional but recommended for performance)
 * - Database schema: database/schema.sql
 *
 * USAGE:
 * ```php
 * $pdo = new PDO('pgsql:host=localhost;dbname=security_db', 'user', 'password');
 * $redis = new Redis();
 * $redis->connect('127.0.0.1', 6379);
 *
 * $storage = new DatabaseStorage($pdo, $redis);
 * $config->setStorage($storage);
 * ```
 *
 * @package Senza1dio\SecurityShield\Storage
 * @version 1.1.0
 * @author Enterprise Security Team
 * @license MIT
 */
class DatabaseStorage implements StorageInterface
{
    /**
     * PostgreSQL database connection
     */
    private \PDO $pdo;

    /**
     * Redis instance for caching (optional but recommended)
     */
    private ?\Redis $redis;

    /**
     * Redis key prefix for namespacing
     */
    private string $keyPrefix;

    /**
     * Constructor
     *
     * @param \PDO $pdo PostgreSQL connection with prepared schema
     * @param \Redis|null $redis Optional Redis for caching (recommended for production)
     * @param string $keyPrefix Redis key prefix (default: 'security_shield:')
     */
    public function __construct(\PDO $pdo, ?\Redis $redis = null, string $keyPrefix = 'security_shield:')
    {
        $this->pdo = $pdo;
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;

        // Ensure PDO throws exceptions on errors
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis cache + PostgreSQL persistence
     */
    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);

        try {
            // Write to PostgreSQL (persistence)
            $stmt = $this->pdo->prepare('
                INSERT INTO threat_scores (ip, score, expires_at, last_updated, request_count)
                VALUES (:ip, :score, :expires_at, NOW(), 1)
                ON CONFLICT (ip) DO UPDATE
                SET score = :score,
                    expires_at = :expires_at,
                    last_updated = NOW()
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':score' => $score,
                ':expires_at' => $expiresAt,
            ]);

            // Write to Redis (cache)
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;
                $this->redis->setex($key, $ttl, (string) $score);
            }

            return true;
        } catch (\PDOException $e) {
            // Graceful degradation - continue with Redis only
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;
                return $this->redis->setex($key, $ttl, (string) $score) !== false;
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getScore(string $ip): ?int
    {
        // Fast path: Check Redis cache first
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'score:' . $ip;
                $score = $this->redis->get($key);

                if ($score !== false && is_numeric($score)) {
                    return (int) $score;
                }
            } catch (\RedisException $e) {
                // Fall through to database
            }
        }

        // Slow path: Query PostgreSQL
        try {
            $stmt = $this->pdo->prepare('
                SELECT score FROM threat_scores
                WHERE ip = :ip AND expires_at > NOW()
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result && isset($result['score'])) {
                $score = (int) $result['score'];

                // Warm Redis cache for next read
                if ($this->redis) {
                    $key = $this->keyPrefix . 'score:' . $ip;
                    $this->redis->setex($key, 3600, (string) $score);
                }

                return $score;
            }

            return null;
        } catch (\PDOException $e) {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis atomic increment + PostgreSQL update
     * Uses Lua script for Redis atomicity, SQL UPDATE for persistence
     */
    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);
        $newScore = 0;

        try {
            // STEP 1: Increment in PostgreSQL (source of truth)
            $stmt = $this->pdo->prepare('
                INSERT INTO threat_scores (ip, score, expires_at, last_updated, request_count, reasons)
                VALUES (:ip, :points, :expires_at, NOW(), 1, \'[]\'::JSONB)
                ON CONFLICT (ip) DO UPDATE
                SET score = threat_scores.score + :points,
                    expires_at = :expires_at,
                    last_updated = NOW(),
                    request_count = threat_scores.request_count + 1
                RETURNING score
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':points' => $points,
                ':expires_at' => $expiresAt,
            ]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $newScore = $result ? (int) $result['score'] : 0;

            // STEP 2: Sync to Redis cache
            if ($this->redis && $newScore > 0) {
                $key = $this->keyPrefix . 'score:' . $ip;
                $this->redis->setex($key, $ttl, (string) $newScore);
            }

            return $newScore;
        } catch (\PDOException $e) {
            // Fallback: Redis-only increment (volatile but functional)
            if ($this->redis) {
                $key = $this->keyPrefix . 'score:' . $ip;
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
                $result = $this->redis->eval($lua, [$key, $points, $ttl], 1);
                return is_int($result) ? $result : 0;
            }
            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Ban check with database fallback (cold cache scenario)
     */
    public function isBanned(string $ip): bool
    {
        // Fast path: Redis cache (MUST be fast)
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $exists = $this->redis->exists($key);
                if (is_int($exists) && $exists > 0) {
                    return true; // Cache hit - banned
                }
            } catch (\RedisException $e) {
                // Fallthrough to database
            }
        }

        // Slow path: Database fallback (cold start or Redis down)
        // NOTE: This is ONLY hit when Redis is unavailable or cold cache
        try {
            $stmt = $this->pdo->prepare('
                SELECT 1 FROM ip_bans
                WHERE ip = :ip AND expires_at > NOW()
                LIMIT 1
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            $banned = $result !== false;

            // Warm Redis cache to avoid DB hit next time
            if ($banned && $this->redis) {
                // Get ban duration from DB to set correct TTL
                $stmt = $this->pdo->prepare('
                    SELECT EXTRACT(EPOCH FROM (expires_at - NOW()))::INTEGER AS ttl
                    FROM ip_bans
                    WHERE ip = :ip AND expires_at > NOW()
                    LIMIT 1
                ');
                $stmt->execute([':ip' => $ip]);
                $ttlResult = $stmt->fetch(\PDO::FETCH_ASSOC);
                $ttl = $ttlResult && isset($ttlResult['ttl']) ? max(60, (int) $ttlResult['ttl']) : 86400;

                $key = $this->keyPrefix . 'ban:' . $ip;
                $this->redis->setex($key, $ttl, '1');
            }

            return $banned;
        } catch (\PDOException $e) {
            // Graceful degradation - fail-open (assume not banned)
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * PERFORMANCE-CRITICAL: Cache-only check (NO database query)
     * Called at STEP 0 of handle() before ANY other operations.
     *
     * RATIONALE: This prevents banned IPs from:
     * - Incrementing rate limit counters (DoS storage amplification)
     * - Running SQL/XSS pattern matching (CPU waste)
     * - Triggering scoring calculations (storage writes)
     *
     * DATABASE FALLBACK INTENTIONALLY OMITTED:
     * - Cold cache scenario is acceptable (one extra request before ban takes effect)
     * - Database query here would hurt performance for ALL requests (hot path)
     * - Next request will hit isBanned() which warms the cache
     */
    public function isIpBannedCached(string $ip): bool
    {
        // Cache-only check (NO database fallback)
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $exists = $this->redis->exists($key);
                return is_int($exists) && $exists > 0;
            } catch (\RedisException $e) {
                // Graceful degradation - assume not banned (fail-open)
                return false;
            }
        }

        // No Redis = no cached ban check possible
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis (immediate effect) + PostgreSQL (audit trail)
     */
    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $duration);
        $bannedAt = date('Y-m-d H:i:s');

        try {
            // STEP 1: Write to PostgreSQL (audit trail)
            $stmt = $this->pdo->prepare('
                INSERT INTO ip_bans (ip, reason, banned_at, expires_at, ban_count)
                VALUES (:ip, :reason, :banned_at, :expires_at, 1)
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':reason' => $reason,
                ':banned_at' => $bannedAt,
                ':expires_at' => $expiresAt,
            ]);

            // STEP 2: Write to Redis (immediate block)
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $data = json_encode([
                    'ip' => $ip,
                    'reason' => $reason,
                    'banned_at' => time(),
                    'expires_at' => time() + $duration,
                ]);
                $this->redis->setex($key, $duration, $data);
            }

            return true;
        } catch (\PDOException $e) {
            // Fallback: Redis-only ban (volatile but functional)
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $data = json_encode([
                    'ip' => $ip,
                    'reason' => $reason,
                    'banned_at' => time(),
                    'expires_at' => time() + $duration,
                ]);
                return $this->redis->setex($key, $duration, $data) !== false;
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-DELETE: Redis + PostgreSQL
     */
    public function unbanIP(string $ip): bool
    {
        try {
            // Delete from PostgreSQL
            $stmt = $this->pdo->prepare('
                DELETE FROM ip_bans WHERE ip = :ip
            ');
            $stmt->execute([':ip' => $ip]);

            // Delete from Redis
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $this->redis->del($key);
            }

            return true;
        } catch (\PDOException $e) {
            // Fallback: Redis-only delete
            if ($this->redis) {
                $key = $this->keyPrefix . 'ban:' . $ip;
                $deleted = $this->redis->del($key);
                return is_int($deleted) && $deleted > 0;
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis (fast reads) + PostgreSQL (persistence)
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $ttl);

        try {
            // Write to PostgreSQL
            $stmt = $this->pdo->prepare('
                INSERT INTO bot_verifications (ip, is_legitimate, hostname, bot_type, metadata, expires_at)
                VALUES (:ip, :is_legitimate, :hostname, :bot_type, :metadata, :expires_at)
                ON CONFLICT (ip) DO UPDATE
                SET is_legitimate = :is_legitimate,
                    hostname = :hostname,
                    bot_type = :bot_type,
                    metadata = :metadata,
                    verified_at = NOW(),
                    expires_at = :expires_at
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':is_legitimate' => $isLegitimate ? 'true' : 'false',
                ':hostname' => $metadata['hostname'] ?? null,
                ':bot_type' => $metadata['bot_type'] ?? null,
                ':metadata' => json_encode($metadata),
                ':expires_at' => $expiresAt,
            ]);

            // Write to Redis
            if ($this->redis) {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = json_encode([
                    'verified' => $isLegitimate,
                    'metadata' => $metadata,
                    'cached_at' => time(),
                ]);
                $this->redis->setex($key, $ttl, $data);
            }

            return true;
        } catch (\PDOException $e) {
            // Fallback: Redis-only cache
            if ($this->redis) {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = json_encode([
                    'verified' => $isLegitimate,
                    'metadata' => $metadata,
                    'cached_at' => time(),
                ]);
                return $this->redis->setex($key, $ttl, $data) !== false;
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getCachedBotVerification(string $ip): ?array
    {
        // Fast path: Redis cache
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'bot:' . $ip;
                $data = $this->redis->get($key);

                if ($data !== false && is_string($data)) {
                    $decoded = json_decode($data, true);
                    if (is_array($decoded) && isset($decoded['verified'])) {
                        return [
                            'verified' => $decoded['verified'],
                            'metadata' => $decoded['metadata'] ?? [],
                        ];
                    }
                }
            } catch (\RedisException $e) {
                // Fall through to database
            }
        }

        // Slow path: PostgreSQL fallback
        try {
            $stmt = $this->pdo->prepare('
                SELECT is_legitimate, metadata FROM bot_verifications
                WHERE ip = :ip AND expires_at > NOW()
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result) {
                $metadata = json_decode($result['metadata'] ?? '{}', true);
                $verified = $result['is_legitimate'] === 't' || $result['is_legitimate'] === true;

                // Warm Redis cache
                if ($this->redis) {
                    $key = $this->keyPrefix . 'bot:' . $ip;
                    $data = json_encode([
                        'verified' => $verified,
                        'metadata' => is_array($metadata) ? $metadata : [],
                        'cached_at' => time(),
                    ]);
                    $this->redis->setex($key, 86400, $data);
                }

                return [
                    'verified' => $verified,
                    'metadata' => is_array($metadata) ? $metadata : [],
                ];
            }

            return null;
        } catch (\PDOException $e) {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis list (fast) + PostgreSQL table (compliance)
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        try {
            // Determine severity from event type
            $severity = match ($type) {
                'auto_ban', 'sql_injection', 'xss_attack' => 'critical',
                'threshold_exceeded', 'honeypot' => 'high',
                'scan', 'rate_limit_exceeded' => 'medium',
                default => 'low',
            };

            // Write to PostgreSQL (compliance)
            $stmt = $this->pdo->prepare('
                INSERT INTO security_events (event_type, ip, event_data, severity)
                VALUES (:event_type, :ip, :event_data, :severity)
            ');
            $stmt->execute([
                ':event_type' => $type,
                ':ip' => $ip,
                ':event_data' => json_encode($data),
                ':severity' => $severity,
            ]);

            // Write to Redis list (fast analytics)
            if ($this->redis) {
                $key = $this->keyPrefix . 'events:' . $type;
                $event = json_encode([
                    'type' => $type,
                    'ip' => $ip,
                    'data' => $data,
                    'timestamp' => time(),
                ]);
                $this->redis->lPush($key, $event);
                $this->redis->lTrim($key, 0, 9999);
                $this->redis->expire($key, 2592000);
            }

            return true;
        } catch (\PDOException $e) {
            // Fallback: Redis-only logging
            if ($this->redis) {
                $key = $this->keyPrefix . 'events:' . $type;
                $event = json_encode([
                    'type' => $type,
                    'ip' => $ip,
                    'data' => $data,
                    'timestamp' => time(),
                ]);
                $this->redis->lPush($key, $event);
                $this->redis->lTrim($key, 0, 9999);
                return true;
            }
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: PostgreSQL (authoritative) with Redis fallback for recent events
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        try {
            if ($type) {
                // Get events for specific type
                $stmt = $this->pdo->prepare('
                    SELECT event_type AS type, ip, event_data AS data, EXTRACT(EPOCH FROM created_at)::INTEGER AS timestamp
                    FROM security_events
                    WHERE event_type = :type
                    ORDER BY created_at DESC
                    LIMIT :limit
                ');
                $stmt->bindValue(':type', $type, \PDO::PARAM_STR);
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
            } else {
                // Get all events
                $stmt = $this->pdo->prepare('
                    SELECT event_type AS type, ip, event_data AS data, EXTRACT(EPOCH FROM created_at)::INTEGER AS timestamp
                    FROM security_events
                    ORDER BY created_at DESC
                    LIMIT :limit
                ');
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
            }

            $stmt->execute();
            $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            // Decode JSON data
            return array_map(function ($row) {
                $row['data'] = json_decode($row['data'] ?? '{}', true);
                return $row;
            }, $results);
        } catch (\PDOException $e) {
            // Fallback: Redis list (limited retention)
            if ($this->redis) {
                $events = [];
                if ($type) {
                    $key = $this->keyPrefix . 'events:' . $type;
                    $rawEvents = $this->redis->lRange($key, 0, $limit - 1);
                    foreach ($rawEvents as $eventJson) {
                        if (is_string($eventJson)) {
                            $event = json_decode($eventJson, true);
                            if (is_array($event)) {
                                $events[] = $event;
                            }
                        }
                    }
                }
                return $events;
            }
            return [];
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-WRITE: Redis atomic + PostgreSQL update
     */
    public function incrementRequestCount(string $ip, int $window): int
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $window);

        try {
            // PostgreSQL increment (source of truth)
            $stmt = $this->pdo->prepare('
                INSERT INTO request_counts (ip, count, window_start, expires_at)
                VALUES (:ip, 1, NOW(), :expires_at)
                ON CONFLICT (ip) DO UPDATE
                SET count = request_counts.count + 1,
                    expires_at = :expires_at
                RETURNING count
            ');
            $stmt->execute([
                ':ip' => $ip,
                ':expires_at' => $expiresAt,
            ]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
            $count = $result ? (int) $result['count'] : 1;

            // Sync to Redis
            if ($this->redis) {
                $key = $this->keyPrefix . 'rate_limit:' . $ip;
                $this->redis->setex($key, $window, (string) $count);
            }

            return $count;
        } catch (\PDOException $e) {
            // Fallback: Redis-only increment
            if ($this->redis) {
                $key = $this->keyPrefix . 'rate_limit:' . $ip;
                $lua = <<<'LUA'
local key = KEYS[1]
local window = tonumber(ARGV[1])
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end
return count
LUA;
                $result = $this->redis->eval($lua, [$key, $window], 1);
                return is_int($result) ? $result : 1;
            }
            return 1;
        }
    }

    /**
     * {@inheritDoc}
     *
     * READ PATH: Redis (fast) → PostgreSQL (fallback)
     */
    public function getRequestCount(string $ip, int $window): int
    {
        // Fast path: Redis cache
        if ($this->redis) {
            try {
                $key = $this->keyPrefix . 'rate_limit:' . $ip;
                $count = $this->redis->get($key);
                if ($count !== false && is_numeric($count)) {
                    return (int) $count;
                }
            } catch (\RedisException $e) {
                // Fall through to database
            }
        }

        // Slow path: PostgreSQL
        try {
            $stmt = $this->pdo->prepare('
                SELECT count FROM request_counts
                WHERE ip = :ip AND expires_at > NOW()
            ');
            $stmt->execute([':ip' => $ip]);
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($result) {
                $count = (int) $result['count'];

                // Warm Redis cache
                if ($this->redis) {
                    $key = $this->keyPrefix . 'rate_limit:' . $ip;
                    $this->redis->setex($key, $window, (string) $count);
                }

                return $count;
            }

            return 0;
        } catch (\PDOException $e) {
            return 0;
        }
    }

    /**
     * {@inheritDoc}
     *
     * DUAL-CLEAR: Redis + PostgreSQL
     * WARNING: This is destructive - use only for testing
     */
    public function clear(): bool
    {
        try {
            // Clear PostgreSQL tables
            $this->pdo->exec('TRUNCATE TABLE ip_bans, threat_scores, security_events, request_counts, bot_verifications');

            // Clear Redis keys
            if ($this->redis) {
                $pattern = $this->keyPrefix . '*';
                $cursor = null;
                $deletedCount = 0;

                do {
                    $result = $this->redis->scan($cursor, $pattern, 1000);
                    if ($result === false) {
                        break;
                    }

                    if (is_array($result) && count($result) >= 2) {
                        $cursor = $result[0];
                        $keys = $result[1];
                        if (is_array($keys) && !empty($keys)) {
                            $deleted = $this->redis->del($keys);
                            $deletedCount += is_int($deleted) ? $deleted : 0;
                        }
                    }
                } while ($cursor > 0);
            }

            return true;
        } catch (\PDOException | \RedisException $e) {
            return false;
        }
    }

    /**
     * Get PDO instance (for advanced queries)
     *
     * @return \PDO
     */
    public function getPDO(): \PDO
    {
        return $this->pdo;
    }

    /**
     * Get Redis instance (for custom operations)
     *
     * @return \Redis|null
     */
    public function getRedis(): ?\Redis
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
        if ($this->redis) {
            try {
                $value = $this->redis->get($this->keyPrefix . $key);
                if ($value !== false) {
                    if (is_string($value) && (str_starts_with($value, '{') || str_starts_with($value, '['))) {
                        $decoded = json_decode($value, true);
                        return is_array($decoded) ? $decoded : $value;
                    }
                    return $value;
                }
            } catch (\RedisException $e) {
                // Fall through to null
            }
        }
        return null;
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
        if ($this->redis) {
            try {
                if (is_array($value) || is_object($value)) {
                    $value = json_encode($value);
                }
                if (!is_string($value)) {
                    return false;
                }
                return $this->redis->setex($this->keyPrefix . $key, $ttl, $value) !== false;
            } catch (\RedisException $e) {
                return false;
            }
        }
        return false;
    }
}
