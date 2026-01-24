<?php

namespace Senza1dio\SecurityShield\Services\GeoIP;

use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Utils\IPUtils;

/**
 * GeoIP Service - Multi-Provider with Redis Caching
 *
 * ARCHITECTURE:
 * - Multi-provider fallback (primary → secondary → tertiary)
 * - Redis caching (24h TTL to respect API rate limits)
 * - Graceful degradation on all failures
 * - Zero external dependencies (providers optional)
 *
 * PERFORMANCE:
 * - Cache hit: <1ms (Redis GET)
 * - Cache miss: 50-200ms (external API call)
 * - Cache hit rate: >99% in production
 *
 * USAGE:
 * ```php
 * $geoip = new GeoIPService($storage);
 * $geoip->addProvider(new IPApiProvider());
 * $geoip->addProvider(new MaxMindProvider($apiKey));
 *
 * $data = $geoip->lookup('203.0.113.50');
 * // ['country' => 'US', 'city' => 'New York', ...]
 * ```
 *
 * @package Senza1dio\SecurityShield\Services\GeoIP
 */
class GeoIPService
{
    private StorageInterface $storage;

    /** @var array<int, GeoIPInterface> */
    private array $providers = [];

    private int $cacheTTL = 86400; // 24 hours

    private string $cachePrefix = 'geoip:';

    /**
     * @param StorageInterface $storage Redis storage for caching
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add GeoIP provider (order matters - first added = first tried)
     *
     * @param GeoIPInterface $provider
     * @return self
     */
    public function addProvider(GeoIPInterface $provider): self
    {
        $this->providers[] = $provider;
        return $this;
    }

    /**
     * Set cache TTL in seconds
     *
     * DEFAULT: 86400 (24 hours)
     * RECOMMENDED: 43200-86400 (12-24h) to respect API rate limits
     *
     * @param int $seconds Cache TTL (3600-604800, 1h-7days)
     * @return self
     */
    public function setCacheTTL(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 604800) {
            throw new \InvalidArgumentException('Cache TTL must be between 1 hour and 7 days');
        }

        $this->cacheTTL = $seconds;
        return $this;
    }

    /**
     * Lookup IP address with caching and fallback
     *
     * FLOW:
     * 1. Check Redis cache (24h TTL)
     * 2. Try primary provider
     * 3. Fallback to secondary provider
     * 4. Cache result (success or null)
     * 5. Return data or null
     *
     * @param string $ip IPv4 or IPv6 address
     * @return array<string, mixed>|null Geographic data or null on failure
     */
    public function lookup(string $ip): ?array
    {
        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        // Private/reserved IPs = no lookup needed
        if ($this->isPrivateIP($ip)) {
            return [
                'country' => 'ZZ', // Reserved code for unknown
                'country_name' => 'Private Network',
                'is_private' => true,
            ];
        }

        // Check cache first
        $cacheKey = $this->cachePrefix . $ip;
        $cached = $this->getCachedData($cacheKey);

        if ($cached !== null) {
            return $cached;
        }

        // Try all providers in order
        foreach ($this->providers as $provider) {
            if (!$provider->isAvailable()) {
                continue;
            }

            try {
                $data = $provider->lookup($ip);

                if ($data !== null) {
                    // Success - cache and return
                    $this->cacheData($cacheKey, $data);
                    return $data;
                }
            } catch (\Throwable $e) {
                // Provider failed - try next
                continue;
            }
        }

        // All providers failed - cache null to avoid repeated lookups
        $this->cacheData($cacheKey, null);
        return null;
    }

    /**
     * Get country code only (lightweight)
     *
     * @param string $ip
     * @return string|null ISO 3166-1 alpha-2 code or null
     */
    public function getCountry(string $ip): ?string
    {
        $data = $this->lookup($ip);
        $country = $data['country'] ?? null;
        return is_string($country) ? $country : null;
    }

    /**
     * Check if IP is from specific country
     *
     * @param string $ip
     * @param string $countryCode ISO 3166-1 alpha-2 (e.g., 'US', 'IT')
     * @return bool
     */
    public function isCountry(string $ip, string $countryCode): bool
    {
        // Validate ISO 3166-1 alpha-2 country code format
        if (!preg_match('/^[A-Za-z]{2}$/', $countryCode)) {
            throw new \InvalidArgumentException(
                "Country code must be 2 letters (ISO 3166-1 alpha-2), got: {$countryCode}"
            );
        }

        return $this->getCountry($ip) === strtoupper($countryCode);
    }

    /**
     * Check if IP is proxy/VPN
     *
     * @param string $ip
     * @return bool
     */
    public function isProxy(string $ip): bool
    {
        $data = $this->lookup($ip);
        $isProxy = $data['is_proxy'] ?? false;
        return is_bool($isProxy) ? $isProxy : false;
    }

    /**
     * Check if IP is datacenter/hosting
     *
     * @param string $ip
     * @return bool
     */
    public function isDatacenter(string $ip): bool
    {
        $data = $this->lookup($ip);
        $isDatacenter = $data['is_datacenter'] ?? false;
        return is_bool($isDatacenter) ? $isDatacenter : false;
    }

    /**
     * Calculate distance between two locations (haversine formula)
     *
     * @param float $lat1 Latitude of first location
     * @param float $lon1 Longitude of first location
     * @param float $lat2 Latitude of second location
     * @param float $lon2 Longitude of second location
     * @return float Distance in kilometers
     */
    public function calculateDistance(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $earthRadius = 6371; // km

        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);

        $a = sin($dLat / 2) * sin($dLat / 2) +
             cos(deg2rad($lat1)) * cos(deg2rad($lat2)) *
             sin($dLon / 2) * sin($dLon / 2);

        $c = 2 * atan2(sqrt($a), sqrt(1 - $a));

        return $earthRadius * $c;
    }

    /**
     * Check if IP is private/reserved (RFC 1918, RFC 4193)
     *
     * Delegates to IPUtils for centralized private IP detection.
     *
     * @param string $ip
     * @return bool
     */
    private function isPrivateIP(string $ip): bool
    {
        return IPUtils::isPrivateIP($ip);
    }

    /**
     * Get cached GeoIP data
     *
     * NOTE: StorageInterface now includes get()/set() methods.
     * The method_exists check is kept for backward compatibility with
     * custom storage implementations that may not have these methods.
     *
     * @param string $key
     * @return array<string, mixed>|null
     */
    private function getCachedData(string $key): ?array
    {
        // StorageInterface includes get() - check kept for custom implementations
        if (method_exists($this->storage, 'get')) {
            /** @var mixed $data */
            $data = $this->storage->get($key);

            if (is_array($data)) {
                return $data;
            }
        }

        return null;
    }

    /**
     * Cache GeoIP data
     *
     * @param string $key
     * @param array<string, mixed>|null $data
     * @return void
     */
    private function cacheData(string $key, ?array $data): void
    {
        // Use custom cache method if storage supports it
        if (method_exists($this->storage, 'set')) {
            $this->storage->set($key, $data, $this->cacheTTL);
        }
    }

    /**
     * Get all configured providers
     *
     * @return array<int, GeoIPInterface>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }
}
