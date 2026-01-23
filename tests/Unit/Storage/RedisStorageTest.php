<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Storage;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Storage\RedisStorage;

/**
 * Redis Storage Test Suite
 *
 * @covers \Senza1dio\SecurityShield\Storage\RedisStorage
 */
class RedisStorageTest extends TestCase
{
    private \Redis $redis;
    private RedisStorage $storage;

    protected function setUp(): void
    {
        $this->redis = $this->createMock(\Redis::class);
        $this->storage = new RedisStorage($this->redis, 'test:');
    }

    public function testIncrementScoreAtomic(): void
    {
        $this->redis
            ->expects($this->once())
            ->method('eval')
            ->willReturn(15);

        $result = $this->storage->incrementScore('192.168.1.1', 10, 3600);

        $this->assertSame(15, $result);
    }

    public function testIncrementScoreGracefulDegradation(): void
    {
        $this->redis
            ->method('eval')
            ->willThrowException(new \RedisException('Connection lost'));

        $result = $this->storage->incrementScore('192.168.1.1', 10, 3600);

        $this->assertSame(0, $result);
    }

    public function testGetKeyPrefix(): void
    {
        $this->assertSame('test:', $this->storage->getKeyPrefix());
    }

    public function testGetRedisInstance(): void
    {
        $this->assertSame($this->redis, $this->storage->getRedis());
    }
}
