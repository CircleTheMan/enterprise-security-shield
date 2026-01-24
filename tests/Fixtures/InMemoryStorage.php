<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Fixtures;

use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * In-Memory Storage for Testing
 *
 * A simple in-memory implementation of StorageInterface for unit tests.
 * Implements the full StorageInterface for compatibility.
 */
class InMemoryStorage implements StorageInterface
{
    /** @var array<string, array{value: mixed, expires: float|null}> */
    private array $data = [];

    /** @var array<string, int> */
    private array $scores = [];

    /** @var array<string, array{reason: string, expires_at: int}> */
    private array $bans = [];

    /** @var array<string, array{verified: bool, metadata: array<string, mixed>}> */
    private array $botCache = [];

    /** @var array<int, array<string, mixed>> */
    private array $events = [];

    /** @var array<string, array{count: int, expires_at: int}> */
    private array $rateLimits = [];

    public function get(string $key): mixed
    {
        $this->cleanExpired();

        if (!isset($this->data[$key])) {
            return null;
        }

        return $this->data[$key]['value'];
    }

    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $expires = $ttl > 0 ? microtime(true) + $ttl : null;

        $this->data[$key] = [
            'value' => $value,
            'expires' => $expires,
        ];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);
        return true;
    }

    public function exists(string $key): bool
    {
        $this->cleanExpired();
        return isset($this->data[$key]);
    }

    public function clear(): bool
    {
        $this->data = [];
        $this->scores = [];
        $this->bans = [];
        $this->botCache = [];
        $this->events = [];
        $this->rateLimits = [];
        return true;
    }

    public function setScore(string $ip, int $score, int $ttl): bool
    {
        $this->scores[$ip] = $score;
        return true;
    }

    public function getScore(string $ip): ?int
    {
        return $this->scores[$ip] ?? null;
    }

    public function incrementScore(string $ip, int $points, int $ttl): int
    {
        $current = $this->scores[$ip] ?? 0;
        $this->scores[$ip] = $current + $points;
        return $this->scores[$ip];
    }

    public function isBanned(string $ip): bool
    {
        if (!isset($this->bans[$ip])) {
            return false;
        }

        if (time() > $this->bans[$ip]['expires_at']) {
            unset($this->bans[$ip]);
            return false;
        }

        return true;
    }

    public function isIpBannedCached(string $ip): bool
    {
        return $this->isBanned($ip);
    }

    public function banIP(string $ip, int $duration, string $reason): bool
    {
        $this->bans[$ip] = [
            'reason' => $reason,
            'expires_at' => time() + $duration,
        ];
        return true;
    }

    public function unbanIP(string $ip): bool
    {
        unset($this->bans[$ip]);
        return true;
    }

    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool
    {
        $this->botCache[$ip] = [
            'verified' => $isLegitimate,
            'metadata' => $metadata,
        ];
        return true;
    }

    public function getCachedBotVerification(string $ip): ?array
    {
        return $this->botCache[$ip] ?? null;
    }

    public function logSecurityEvent(string $type, string $ip, array $data): bool
    {
        $this->events[] = [
            'type' => $type,
            'ip' => $ip,
            'data' => $data,
            'timestamp' => time(),
        ];
        return true;
    }

    public function getRecentEvents(int $limit = 100, ?string $type = null): array
    {
        $events = $this->events;

        if ($type !== null) {
            $events = array_filter($events, fn($e) => $e['type'] === $type);
        }

        $events = array_reverse($events);
        return array_slice($events, 0, $limit);
    }

    public function incrementRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $key = $ip . ':' . $action;
        $now = time();

        if (!isset($this->rateLimits[$key]) || $now > $this->rateLimits[$key]['expires_at']) {
            $this->rateLimits[$key] = [
                'count' => 1,
                'expires_at' => $now + $window,
            ];
            return 1;
        }

        $this->rateLimits[$key]['count']++;
        return $this->rateLimits[$key]['count'];
    }

    public function getRequestCount(string $ip, int $window, string $action = 'general'): int
    {
        $key = $ip . ':' . $action;

        if (!isset($this->rateLimits[$key])) {
            return 0;
        }

        if (time() > $this->rateLimits[$key]['expires_at']) {
            unset($this->rateLimits[$key]);
            return 0;
        }

        return $this->rateLimits[$key]['count'];
    }

    /**
     * Clean expired entries
     */
    private function cleanExpired(): void
    {
        $now = microtime(true);

        $this->data = array_filter(
            $this->data,
            fn($item) => $item['expires'] === null || $item['expires'] > $now
        );
    }

    /**
     * Get all keys
     *
     * @return array<string>
     */
    public function keys(): array
    {
        $this->cleanExpired();
        return array_keys($this->data);
    }

    /**
     * Get count of stored items
     */
    public function count(): int
    {
        $this->cleanExpired();
        return count($this->data);
    }

    /**
     * {@inheritDoc}
     */
    public function increment(string $key, int $delta, int $ttl): int
    {
        $current = $this->get($key);
        $currentValue = is_numeric($current) ? (int) $current : 0;
        $newValue = $currentValue + $delta;

        if ($newValue < 0) {
            $newValue = 0;
        }

        $this->set($key, (string) $newValue, $ttl);

        return $newValue;
    }
}
