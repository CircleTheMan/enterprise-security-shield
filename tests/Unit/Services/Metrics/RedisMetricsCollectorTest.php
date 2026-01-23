<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Services\Metrics;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Services\Metrics\RedisMetricsCollector;

/**
 * Redis Metrics Collector Test Suite
 *
 * @covers \Senza1dio\SecurityShield\Services\Metrics\RedisMetricsCollector
 */
class RedisMetricsCollectorTest extends TestCase
{
    private \Redis $redis;
    private RedisMetricsCollector $collector;

    protected function setUp(): void
    {
        $this->redis = $this->createMock(\Redis::class);
        $this->collector = new RedisMetricsCollector($this->redis, 'test_metrics:');
    }

    public function testIncrementCallsRedisIncrBy(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('incrBy')
            ->with('test_metrics:requests', 1);

        $this->collector->increment('requests');
    }

    public function testIncrementWithCustomValue(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('incrBy')
            ->with('test_metrics:bytes', 1024);

        $this->collector->increment('bytes', 1024);
    }

    public function testIncrementGracefulDegradation(): void
    {
        $this->redis
            ->method('incrBy')
            ->willThrowException(new \RedisException('Connection lost'));

        // Should not throw exception
        $this->collector->increment('requests');

        $this->expectNotToPerformAssertions();
    }

    public function testGaugeCallsRedisSet(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('set')
            ->with('test_metrics:memory_usage', '512.5');

        $this->collector->gauge('memory_usage', 512.5);
    }

    public function testHistogramAddsToSortedSet(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('zAdd')
            ->with(
                'test_metrics:histogram:response_time',
                $this->isType('float'),
                $this->isType('string')
            );

        $this->redis
            ->expects($this->once())
            ->method('zRemRangeByRank')
            ->with('test_metrics:histogram:response_time', 0, -1001);

        $this->collector->histogram('response_time', 150.5);
    }

    public function testTimingCallsHistogram(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('zAdd');

        $this->redis
            ->expects($this->once())
            ->method('zRemRangeByRank');

        $this->collector->timing('api_latency', 75.3);
    }

    public function testGetReturnsNumericValue(): void
    {
        $this->redis
            ->method('get')
            ->with('test_metrics:requests')
            ->willReturn('1234');

        $result = $this->collector->get('requests');

        $this->assertSame(1234.0, $result);
    }

    public function testGetReturnsNullOnFalse(): void
    {
        $this->redis
            ->method('get')
            ->with('test_metrics:missing')
            ->willReturn(false);

        $result = $this->collector->get('missing');

        $this->assertNull($result);
    }

    public function testGetReturnsNullOnNonNumeric(): void
    {
        $this->redis
            ->method('get')
            ->with('test_metrics:invalid')
            ->willReturn('not-a-number');

        $result = $this->collector->get('invalid');

        $this->assertNull($result);
    }

    public function testGetAllReturnsMetrics(): void
    {
        $this->redis
            ->method('keys')
            ->with('test_metrics:*')
            ->willReturn([
                'test_metrics:requests',
                'test_metrics:errors',
            ]);

        $this->redis
            ->method('get')
            ->willReturnOnConsecutiveCalls('100', '5');

        $result = $this->collector->getAll();

        $this->assertSame([
            'requests' => 100.0,
            'errors' => 5.0,
        ], $result);
    }

    public function testGetAllReturnsEmptyOnException(): void
    {
        $this->redis
            ->method('keys')
            ->willThrowException(new \RedisException('Connection lost'));

        $result = $this->collector->getAll();

        $this->assertSame([], $result);
    }
}
