<?php

namespace Senza1dio\SecurityShield\Services\GeoIP;

/**
 * GeoIP Provider Interface
 *
 * Defines contract for GeoIP lookup providers (MaxMind, ip-api, ipinfo, etc.)
 *
 * @package Senza1dio\SecurityShield\Services\GeoIP
 */
interface GeoIPInterface
{
    /**
     * Lookup IP address and return geographic data
     *
     * @param string $ip IPv4 or IPv6 address
     * @return array<string, mixed>|null Geographic data or null on failure
     *
     * RETURN FORMAT:
     * [
     *     'country' => 'US',              // ISO 3166-1 alpha-2 (2-letter)
     *     'country_name' => 'United States',
     *     'region' => 'California',
     *     'city' => 'San Francisco',
     *     'latitude' => 37.7749,
     *     'longitude' => -122.4194,
     *     'timezone' => 'America/Los_Angeles',
     *     'isp' => 'Cloudflare Inc.',
     *     'asn' => 'AS13335',
     *     'is_proxy' => false,            // VPN/Proxy detection
     *     'is_datacenter' => false,       // Datacenter/hosting IP
     * ]
     */
    public function lookup(string $ip): ?array;

    /**
     * Check if provider is available (API key valid, service reachable)
     *
     * @return bool True if provider ready to use
     */
    public function isAvailable(): bool;

    /**
     * Get provider name (for logging/debugging)
     *
     * @return string Provider name (e.g., 'maxmind', 'ip-api', 'ipinfo')
     */
    public function getName(): string;

    /**
     * Get rate limit info (requests per period)
     *
     * @return array{requests: int, period: string} Rate limit info
     * Example: ['requests' => 45, 'period' => 'minute']
     */
    public function getRateLimit(): array;
}
