<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Services\GeoIP;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Services\GeoIP\GeoIPService;
use Senza1dio\SecurityShield\Services\GeoIP\GeoIPInterface;
use Senza1dio\SecurityShield\Storage\RedisStorage;

/**
 * GeoIP Service Test Suite
 *
 * @covers \Senza1dio\SecurityShield\Services\GeoIP\GeoIPService
 */
class GeoIPServiceTest extends TestCase
{
    private GeoIPService $service;
    private RedisStorage $storage;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(RedisStorage::class);
        $this->service = new GeoIPService($this->storage);
    }

    public function testLookupInvalidIPReturnsNull(): void
    {
        $this->assertNull($this->service->lookup('invalid-ip'));
        $this->assertNull($this->service->lookup('999.999.999.999'));
    }

    public function testLookupPrivateIPReturnsPrivateData(): void
    {
        $result = $this->service->lookup('192.168.1.1');

        $this->assertIsArray($result);
        $this->assertSame('ZZ', $result['country']);
        $this->assertSame('Private Network', $result['country_name']);
        $this->assertTrue($result['is_private']);
    }

    public function testLookupCacheHit(): void
    {
        $cachedData = [
            'country' => 'US',
            'country_name' => 'United States',
            'city' => 'New York',
        ];

        $this->storage
            ->expects($this->once())
            ->method('get')
            ->with('geoip:8.8.8.8')
            ->willReturn($cachedData);

        $result = $this->service->lookup('8.8.8.8');

        $this->assertSame($cachedData, $result);
    }

    public function testLookupProviderFallback(): void
    {
        // Mock storage returns null (cache miss)
        $this->storage
            ->method('get')
            ->willReturn(null);

        // Mock primary provider fails
        $primaryProvider = $this->createMock(GeoIPInterface::class);
        $primaryProvider
            ->method('isAvailable')
            ->willReturn(true);
        $primaryProvider
            ->method('lookup')
            ->willReturn(null);

        // Mock secondary provider succeeds
        $secondaryProvider = $this->createMock(GeoIPInterface::class);
        $secondaryProvider
            ->method('isAvailable')
            ->willReturn(true);
        $secondaryProvider
            ->method('lookup')
            ->willReturn([
                'country' => 'IT',
                'country_name' => 'Italy',
            ]);

        $this->storage
            ->expects($this->once())
            ->method('set')
            ->with('geoip:8.8.8.8', $this->isType('array'), 86400);

        $this->service->addProvider($primaryProvider);
        $this->service->addProvider($secondaryProvider);

        $result = $this->service->lookup('8.8.8.8');

        $this->assertSame('IT', $result['country']);
    }

    public function testLookupAllProvidersFail(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(null);

        $provider = $this->createMock(GeoIPInterface::class);
        $provider
            ->method('isAvailable')
            ->willReturn(true);
        $provider
            ->method('lookup')
            ->willReturn(null);

        // Should cache null to avoid repeated lookups
        $this->storage
            ->expects($this->once())
            ->method('set')
            ->with('geoip:8.8.8.8', null, 86400);

        $this->service->addProvider($provider);

        $result = $this->service->lookup('8.8.8.8');

        $this->assertNull($result);
    }

    public function testGetCountryReturnsCorrectValue(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['country' => 'US']);

        $result = $this->service->getCountry('8.8.8.8');

        $this->assertSame('US', $result);
    }

    public function testGetCountryReturnsNullOnMissingData(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['city' => 'New York']); // No country field

        $result = $this->service->getCountry('8.8.8.8');

        $this->assertNull($result);
    }

    public function testIsCountryReturnsTrueForMatch(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['country' => 'IT']);

        $this->assertTrue($this->service->isCountry('8.8.8.8', 'IT'));
        $this->assertTrue($this->service->isCountry('8.8.8.8', 'it')); // Case insensitive
    }

    public function testIsCountryReturnsFalseForNoMatch(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['country' => 'US']);

        $this->assertFalse($this->service->isCountry('8.8.8.8', 'IT'));
    }

    public function testIsProxyDetection(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['is_proxy' => true]);

        $this->assertTrue($this->service->isProxy('8.8.8.8'));
    }

    public function testIsDatacenterDetection(): void
    {
        $this->storage
            ->method('get')
            ->willReturn(['is_datacenter' => true]);

        $this->assertTrue($this->service->isDatacenter('8.8.8.8'));
    }

    public function testCalculateDistanceAccurate(): void
    {
        // New York to Los Angeles
        $lat1 = 40.7128;
        $lon1 = -74.0060;
        $lat2 = 34.0522;
        $lon2 = -118.2437;

        $distance = $this->service->calculateDistance($lat1, $lon1, $lat2, $lon2);

        // Real distance is ~3944 km
        $this->assertGreaterThan(3900, $distance);
        $this->assertLessThan(4000, $distance);
    }

    public function testCalculateDistanceSameLocation(): void
    {
        $distance = $this->service->calculateDistance(40.0, -74.0, 40.0, -74.0);

        $this->assertSame(0.0, $distance);
    }

    public function testSetCacheTTLValid(): void
    {
        $this->service->setCacheTTL(43200); // 12 hours

        $this->expectNotToPerformAssertions();
    }

    public function testSetCacheTTLInvalidThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cache TTL must be between 1 hour and 7 days');

        $this->service->setCacheTTL(1800); // 30 minutes (too low)
    }

    public function testGetProvidersReturnsEmptyArray(): void
    {
        $this->assertEmpty($this->service->getProviders());
    }

    public function testGetProvidersReturnsAddedProviders(): void
    {
        $provider = $this->createMock(GeoIPInterface::class);
        $this->service->addProvider($provider);

        $providers = $this->service->getProviders();

        $this->assertCount(1, $providers);
        $this->assertSame($provider, $providers[0]);
    }
}
