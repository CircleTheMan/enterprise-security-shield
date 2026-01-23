<?php

namespace Senza1dio\SecurityShield\Services\GeoIP;

/**
 * IP-API.com Provider - FREE GeoIP Service
 *
 * FREE TIER:
 * - 45 requests per minute
 * - No API key required
 * - HTTPS support
 * - Proxy/VPN detection included
 *
 * RECOMMENDED FOR:
 * - Small to medium sites (<2000 requests/hour)
 * - Development/testing
 * - Budget-conscious deployments
 *
 * API DOCS: https://ip-api.com/docs/api:json
 *
 * @package Senza1dio\SecurityShield\Services\GeoIP
 */
class IPApiProvider implements GeoIPInterface
{
    private const API_URL = 'http://ip-api.com/json';
    private const API_URL_HTTPS = 'https://pro.ip-api.com/json'; // Requires paid plan
    private const TIMEOUT = 2; // 2 seconds timeout

    private bool $useHTTPS;
    private ?string $apiKey;

    /**
     * @param bool $useHTTPS Use HTTPS API (requires paid plan + API key)
     * @param string|null $apiKey API key for paid plan (optional)
     */
    public function __construct(bool $useHTTPS = false, ?string $apiKey = null)
    {
        $this->useHTTPS = $useHTTPS;
        $this->apiKey = $apiKey;
    }

    /**
     * {@inheritDoc}
     */
    public function lookup(string $ip): ?array
    {
        // Build API URL
        $url = $this->useHTTPS ? self::API_URL_HTTPS : self::API_URL;
        $url .= "/{$ip}";

        // Add fields parameter (optimize response size)
        $fields = [
            'status', 'country', 'countryCode', 'region', 'regionName',
            'city', 'lat', 'lon', 'timezone', 'isp', 'org', 'as', 'proxy'
        ];
        $url .= '?fields=' . implode(',', $fields);

        // Add API key for paid plan
        if ($this->apiKey) {
            $url .= '&key=' . $this->apiKey;
        }

        try {
            // cURL request with timeout
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => self::TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => 1,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false || !is_string($response) || $httpCode !== 200) {
                return null;
            }

            $data = json_decode($response, true);

            if (!is_array($data) || ($data['status'] ?? '') !== 'success') {
                return null;
            }

            // Normalize to standard format
            return [
                'country' => $data['countryCode'] ?? null,
                'country_name' => $data['country'] ?? null,
                'region' => $data['regionName'] ?? null,
                'city' => $data['city'] ?? null,
                'latitude' => isset($data['lat']) ? (float) $data['lat'] : null,
                'longitude' => isset($data['lon']) ? (float) $data['lon'] : null,
                'timezone' => $data['timezone'] ?? null,
                'isp' => $data['isp'] ?? $data['org'] ?? null,
                'asn' => $data['as'] ?? null,
                'is_proxy' => isset($data['proxy']) ? (bool) $data['proxy'] : false,
                'is_datacenter' => $this->isDatacenterFromISP($data['isp'] ?? '', $data['org'] ?? ''),
            ];

        } catch (\Throwable $e) {
            // Graceful degradation
            return null;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isAvailable(): bool
    {
        // ip-api.com has no auth, always available (unless rate limited)
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        return 'ip-api';
    }

    /**
     * {@inheritDoc}
     */
    public function getRateLimit(): array
    {
        return [
            'requests' => $this->useHTTPS ? 500 : 45, // HTTPS paid plan = 500/min
            'period' => 'minute',
        ];
    }

    /**
     * Detect datacenter IPs from ISP/Org name
     *
     * Common patterns: AWS, Google Cloud, Azure, DigitalOcean, Linode, etc.
     *
     * @param string $isp ISP name
     * @param string $org Organization name
     * @return bool True if likely datacenter
     */
    private function isDatacenterFromISP(string $isp, string $org): bool
    {
        $datacenterKeywords = [
            'amazon', 'aws', 'ec2', 'google cloud', 'gcp', 'microsoft azure',
            'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'contabo',
            'rackspace', 'hostinger', 'hostgator', 'godaddy', 'namecheap',
            'cloudflare', 'fastly', 'akamai', 'cdn', 'hosting', 'datacenter',
            'dedicated', 'vps', 'colocation', 'serverius', 'psychz',
        ];

        $combined = strtolower($isp . ' ' . $org);

        foreach ($datacenterKeywords as $keyword) {
            if (strpos($combined, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }
}
