<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Services\GeoIP\GeoIPService;
use Senza1dio\SecurityShield\Services\GeoIP\IPApiProvider;

/**
 * Example 2: GeoIP-Based Country Blocking
 *
 * Block requests from specific countries.
 * Useful for:
 * - Compliance (GDPR, data sovereignty)
 * - Threat mitigation (block high-risk regions)
 * - Service restrictions (region-specific content)
 */

// 1. Setup Redis and storage
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$storage = new RedisStorage($redis, 'security_shield:');

// 2. Setup GeoIP service
$geoipService = new GeoIPService($storage);
$geoipService->addProvider(new IPApiProvider()); // Free provider, no API key needed
$geoipService->setCacheTTL(86400); // Cache 24 hours to respect API limits

// 3. Configure security with GeoIP blocking
$config = new SecurityConfig();
$config
    ->setEnabled(true)
    ->setBanDuration(86400) // 24 hour ban for blocked countries
    ->setAutoBlockThreshold(50)
    ->setGeoIPEnabled(true)
    ->setBlockedCountries(['CN', 'RU', 'KP', 'IR']); // Block China, Russia, North Korea, Iran

// 4. Create WAF with GeoIP integration
$waf = new WafMiddleware($config, $storage);
$waf->setGeoIPService($geoipService);

// 5. Process request
$clientIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$allowed = $waf->handle($_SERVER);

if (!$allowed) {
    $reason = $waf->getBlockReason();

    // Check if blocked due to geo-blocking
    if (str_starts_with($reason, 'geo_blocked_')) {
        $country = substr($reason, strlen('geo_blocked_'));

        http_response_code(403);
        echo json_encode([
            'error' => 'Geographic Restriction',
            'country' => $country,
            'message' => 'Access from your country is not permitted.',
        ]);
        exit;
    }

    // Other block reason
    http_response_code(403);
    echo json_encode(['error' => 'Access Denied', 'reason' => $reason]);
    exit;
}

// Get GeoIP data for allowed request (optional)
$geoData = $geoipService->lookup($clientIP);
if ($geoData) {
    echo "✅ Request allowed from {$geoData['country_name']} ({$geoData['country']})\n";
    echo "   City: {$geoData['city']}\n";
    echo "   ISP: {$geoData['isp']}\n";

    if ($geoData['is_proxy']) {
        echo "   ⚠️  Warning: Request from proxy/VPN detected\n";
    }

    if ($geoData['is_datacenter']) {
        echo "   ⚠️  Warning: Request from datacenter IP detected\n";
    }
}
