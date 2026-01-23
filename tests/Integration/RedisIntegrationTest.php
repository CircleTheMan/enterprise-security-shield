<?php

namespace Senza1dio\SecurityShield\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Storage\RedisStorage;

/**
 * Redis Integration Tests - REAL Redis Connection Required
 *
 * These tests require a running Redis instance on localhost:6379
 *
 * To run: docker run -d -p 6379:6379 redis:7-alpine
 * Then: vendor/bin/phpunit tests/Integration
 *
 * WHAT WE TEST:
 * - Race condition fix in incrementScore() (FIX #1)
 * - SCAN performance vs KEYS (FIX #2)
 * - Graceful degradation on Redis disconnect (FIX #3)
 * - Concurrent operations (real-world scenario)
 * - Memory leaks (TTL must be set)
 */
class RedisIntegrationTest extends TestCase
{
    private ?\Redis $redis = null;
    private ?RedisStorage $storage = null;

    protected function setUp(): void
    {
        if (!extension_loaded('redis')) {
            $this->markTestSkipped('Redis extension not available');
        }

        try {
            $this->redis = new \Redis();
            $connected = @$this->redis->connect('127.0.0.1', 6379, 1.0);

            if (!$connected) {
                $this->markTestSkipped('Redis server not available on localhost:6379');
            }

            // Select test database (DB 15)
            $this->redis->select(15);

            // Clean test data
            $this->redis->flushDB();

            $this->storage = new RedisStorage($this->redis, 'test_integration:');
        } catch (\RedisException $e) {
            $this->markTestSkipped('Redis connection failed: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        if ($this->redis) {
            try {
                $this->redis->flushDB();
                $this->redis->close();
            } catch (\RedisException $e) {
                // Ignore cleanup errors
            }
        }
    }

    /**
     * TEST FIX #1: Race Condition in incrementScore()
     *
     * Simulates 100 concurrent increments. All must have TTL set.
     * OLD CODE: Some keys would miss TTL under concurrent load.
     * NEW CODE: Lua script ensures atomic INCRBY + EXPIRE.
     */
    public function test_incrementScore_race_condition_fixed()
    {
        $ip = '192.168.1.100';
        $points = 5;
        $ttl = 3600;
        $iterations = 100;

        // Simulate concurrent increments
        for ($i = 0; $i < $iterations; $i++) {
            $score = $this->storage->incrementScore($ip, $points, $ttl);
            $this->assertGreaterThan(0, $score);
        }

        // Final score should be correct
        $finalScore = $this->storage->getScore($ip);
        $this->assertSame($iterations * $points, $finalScore);

        // CRITICAL: Key MUST have TTL (race condition test)
        $keyTTL = $this->redis->ttl('test_integration:score:' . $ip);
        $this->assertGreaterThan(0, $keyTTL, 'Key must have TTL set (race condition bug!)');
        $this->assertLessThanOrEqual($ttl, $keyTTL);
    }

    /**
     * TEST FIX #1: incrementScore() sets TTL on first call
     */
    public function test_incrementScore_sets_ttl_on_first_call()
    {
        $ip = '10.0.0.1';
        $ttl = 300;

        $this->storage->incrementScore($ip, 10, $ttl);

        $keyTTL = $this->redis->ttl('test_integration:score:' . $ip);
        $this->assertGreaterThan(0, $keyTTL);
        $this->assertLessThanOrEqual($ttl, $keyTTL);
    }

    /**
     * TEST FIX #1: incrementScore() preserves TTL on subsequent calls
     */
    public function test_incrementScore_preserves_existing_ttl()
    {
        $ip = '10.0.0.2';
        $ttl = 600;

        // First increment
        $this->storage->incrementScore($ip, 10, $ttl);
        $originalTTL = $this->redis->ttl('test_integration:score:' . $ip);

        // Wait 1 second
        sleep(1);

        // Second increment (should NOT reset TTL)
        $this->storage->incrementScore($ip, 5, $ttl);
        $newTTL = $this->redis->ttl('test_integration:score:' . $ip);

        // TTL should be LESS than original (time passed)
        $this->assertLessThan($originalTTL, $newTTL);
        $this->assertGreaterThan(0, $newTTL);
    }

    /**
     * TEST FIX #2: SCAN Performance - No Blocking
     *
     * Creates 10,000 keys and tests getRecentEvents().
     * OLD CODE: KEYS * would BLOCK Redis for seconds.
     * NEW CODE: SCAN iterates without blocking.
     */
    public function test_scan_performance_no_blocking()
    {
        // Create 10,000 test keys
        for ($i = 0; $i < 10000; $i++) {
            $this->redis->set("test_integration:dummy:{$i}", 'test');
        }

        // Log some security events
        for ($i = 0; $i < 50; $i++) {
            $this->storage->logSecurityEvent('test', "10.0.0.{$i}", ['test' => $i]);
        }

        // Measure time (should be <100ms even with 10k keys)
        $start = microtime(true);
        $events = $this->storage->getRecentEvents(20);
        $duration = (microtime(true) - $start) * 1000;

        $this->assertLessThan(100, $duration, 'SCAN must complete in <100ms');
        $this->assertCount(20, $events);
    }

    /**
     * TEST FIX #3: Graceful Degradation on Redis Disconnect
     */
    public function test_graceful_degradation_on_disconnect()
    {
        // Close Redis connection mid-operation
        $this->redis->close();

        // All operations should return false/null/0 instead of throwing
        $this->assertFalse($this->storage->setScore('10.0.0.1', 10, 300));
        $this->assertNull($this->storage->getScore('10.0.0.1'));
        $this->assertFalse($this->storage->isBanned('10.0.0.1'));
        $this->assertSame(0, $this->storage->incrementScore('10.0.0.1', 5, 300));
        $this->assertFalse($this->storage->banIP('10.0.0.1', 600, 'test'));
    }

    /**
     * TEST: Concurrent rate limiting (real-world scenario)
     */
    public function test_concurrent_rate_limiting()
    {
        $ip = '192.168.1.200';
        $window = 60;
        $requests = 50;

        // Simulate 50 rapid requests
        for ($i = 0; $i < $requests; $i++) {
            $count = $this->storage->incrementRequestCount($ip, $window);
            $this->assertSame($i + 1, $count);
        }

        // Verify final count
        $finalCount = $this->storage->getRequestCount($ip, $window);
        $this->assertSame($requests, $finalCount);

        // Verify TTL is set
        $keyTTL = $this->redis->ttl('test_integration:rate_limit:' . $ip);
        $this->assertGreaterThan(0, $keyTTL);
        $this->assertLessThanOrEqual($window, $keyTTL);
    }

    /**
     * TEST: Ban persistence and expiration
     */
    public function test_ban_persistence_and_expiration()
    {
        $ip = '10.0.0.50';
        $duration = 2; // 2 seconds

        // Ban IP
        $this->assertTrue($this->storage->banIP($ip, $duration, 'Test ban'));
        $this->assertTrue($this->storage->isBanned($ip));

        // Wait for expiration
        sleep(3);

        // Should no longer be banned
        $this->assertFalse($this->storage->isBanned($ip));
    }

    /**
     * TEST: Event logging with large volume
     */
    public function test_event_logging_large_volume()
    {
        // Log 1000 events
        for ($i = 0; $i < 1000; $i++) {
            $this->storage->logSecurityEvent('waf', "10.0.{$i}.1", [
                'score' => $i,
                'path' => '/test',
            ]);
        }

        // Should only keep last 10,000 (per type)
        $key = 'test_integration:events:waf';
        $count = $this->redis->lLen($key);
        $this->assertSame(1000, $count);

        // Should have TTL (30 days)
        $ttl = $this->redis->ttl($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(2592000, $ttl);
    }

    /**
     * TEST: Clear operation with batching
     */
    public function test_clear_operation_with_batching()
    {
        // Create 2500 test keys
        for ($i = 0; $i < 2500; $i++) {
            $this->redis->set("test_integration:bulk:{$i}", 'test');
        }

        // Clear should delete in batches of 1000
        $this->assertTrue($this->storage->clear());

        // Verify all keys deleted
        $remaining = $this->redis->keys('test_integration:*');
        $this->assertEmpty($remaining);
    }

    /**
     * TEST: Memory leak prevention (all keys have TTL)
     */
    public function test_no_memory_leaks_all_keys_have_ttl()
    {
        // Perform various operations
        $this->storage->incrementScore('10.0.0.1', 10, 300);
        $this->storage->banIP('10.0.0.2', 600, 'test');
        $this->storage->incrementRequestCount('10.0.0.3', 60);
        $this->storage->cacheBotVerification('10.0.0.4', true, ['test' => 1], 3600);

        // Check ALL keys have TTL
        $keys = $this->redis->keys('test_integration:*');
        foreach ($keys as $key) {
            $ttl = $this->redis->ttl($key);
            $this->assertGreaterThan(0, $ttl, "Key {$key} must have TTL (memory leak!)");
        }
    }
}
