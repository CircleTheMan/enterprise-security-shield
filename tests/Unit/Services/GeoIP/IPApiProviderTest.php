<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Services\GeoIP;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Services\GeoIP\IPApiProvider;

/**
 * IP-API Provider Test Suite
 *
 * @covers \Senza1dio\SecurityShield\Services\GeoIP\IPApiProvider
 */
class IPApiProviderTest extends TestCase
{
    private IPApiProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new IPApiProvider();
    }

    public function testIsAvailableReturnsTrue(): void
    {
        $this->assertTrue($this->provider->isAvailable());
    }

    public function testGetNameReturnsCorrectName(): void
    {
        $this->assertSame('ip-api', $this->provider->getName());
    }

    public function testGetRateLimitReturnsFreeLimit(): void
    {
        $rateLimit = $this->provider->getRateLimit();

        $this->assertSame(45, $rateLimit['requests']);
        $this->assertSame('minute', $rateLimit['period']);
    }

    public function testGetRateLimitReturnsHttpsLimit(): void
    {
        $provider = new IPApiProvider(true, 'test-key');
        $rateLimit = $provider->getRateLimit();

        $this->assertSame(500, $rateLimit['requests']);
        $this->assertSame('minute', $rateLimit['period']);
    }

    /**
     * Integration test - requires internet connection
     * @group integration
     */
    public function testLookupRealIP(): void
    {
        $result = $this->provider->lookup('8.8.8.8');

        if ($result === null) {
            $this->markTestSkipped('IP-API service unavailable or rate limited');
        }

        $this->assertIsArray($result);
        $this->assertArrayHasKey('country', $result);
        $this->assertArrayHasKey('country_name', $result);
        $this->assertSame('US', $result['country']); // Google DNS is US
    }

    /**
     * Integration test - datacenter detection
     * @group integration
     */
    public function testLookupDetectsDatacenter(): void
    {
        // AWS IP address
        $result = $this->provider->lookup('52.95.110.1');

        if ($result === null) {
            $this->markTestSkipped('IP-API service unavailable or rate limited');
        }

        $this->assertIsArray($result);
        $this->assertTrue($result['is_datacenter'] ?? false);
    }
}
