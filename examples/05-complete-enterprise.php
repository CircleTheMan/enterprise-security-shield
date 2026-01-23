<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Services\GeoIP\GeoIPService;
use Senza1dio\SecurityShield\Services\GeoIP\IPApiProvider;
use Senza1dio\SecurityShield\Services\Metrics\RedisMetricsCollector;
use Senza1dio\SecurityShield\Services\WebhookNotifier;
use Psr\Log\LoggerInterface;

/**
 * Example 5: Complete Enterprise Setup
 *
 * Full-featured security stack with all bells and whistles:
 * - WAF with threat scoring
 * - GeoIP-based blocking
 * - Metrics collection
 * - Webhook notifications
 * - Honeypot traps
 * - Bot verification
 * - Rate limiting
 * - Trusted proxy support
 * - PSR-3 logging
 */

// ============================================================================
// 1. REDIS SETUP (Single instance, multiple DBs for separation)
// ============================================================================
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('your-redis-password');
$redis->select(0); // DB 0 for security data

// ============================================================================
// 2. STORAGE BACKEND
// ============================================================================
$storage = new RedisStorage($redis, 'security_shield:');

// ============================================================================
// 3. GEOIP SERVICE (with multi-provider fallback)
// ============================================================================
$geoipService = new GeoIPService($storage);
$geoipService->addProvider(new IPApiProvider()); // Free provider (45 req/min)
// $geoipService->addProvider(new MaxMindProvider($apiKey)); // Paid provider (fallback)
$geoipService->setCacheTTL(86400); // 24h cache

// ============================================================================
// 4. METRICS COLLECTOR
// ============================================================================
$metricsRedis = new Redis();
$metricsRedis->connect('127.0.0.1', 6379);
$metricsRedis->auth('your-redis-password');
$metricsRedis->select(1); // DB 1 for metrics (separation)

$metrics = new RedisMetricsCollector($metricsRedis, 'security_metrics:');

// ============================================================================
// 5. WEBHOOK NOTIFIER (Slack, Discord, custom)
// ============================================================================
$webhooks = new WebhookNotifier();
$webhooks
    ->addWebhook('slack', getenv('SLACK_WEBHOOK_URL'))
    ->addWebhook('discord', getenv('DISCORD_WEBHOOK_URL'))
    ->setTimeout(3)
    ->setAsync(true); // Non-blocking webhooks

// ============================================================================
// 6. PSR-3 LOGGER (Monolog example)
// ============================================================================
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;

$logger = new Logger('security');
$logger->pushHandler(new RotatingFileHandler(__DIR__ . '/../logs/security.log', 30, Logger::WARNING));
$logger->pushHandler(new StreamHandler('php://stdout', Logger::INFO));

// ============================================================================
// 7. SECURITY CONFIGURATION (Production-grade)
// ============================================================================
$config = new SecurityConfig();
$config
    // Core settings
    ->setEnabled(true)
    ->setBanDuration(3600)              // 1 hour ban
    ->setScoreTTL(900)                  // 15 minutes score retention
    ->setAutoBlockThreshold(100)        // Auto-ban at 100 points
    ->setBlockedResponseCode(403)

    // Attack detection thresholds
    ->setSQLInjectionThreshold(50)      // +50 points for SQL injection
    ->setXSSThreshold(40)               // +40 points for XSS
    ->setPathTraversalThreshold(45)     // +45 points for path traversal
    ->setCommandInjectionThreshold(80)  // +80 points for command injection

    // Rate limiting
    ->setRateLimitEnabled(true)
    ->setRateLimitWindow(60)            // 60 seconds
    ->setRateLimitMaxRequests(100)      // 100 requests per minute

    // Honeypot traps
    ->setHoneypotEnabled(true)
    ->setHoneypotPaths([
        '/admin/config.php',
        '/wp-admin/setup-config.php',
        '/.env',
        '/phpmyadmin/index.php',
        '/backup.sql',
    ])

    // GeoIP blocking
    ->setGeoIPEnabled(true)
    ->setBlockedCountries(['CN', 'RU', 'KP', 'IR']) // Adjust as needed

    // Trusted proxies (Cloudflare, AWS, etc.)
    ->setTrustedProxies([
        '173.245.48.0/20',   // Cloudflare
        '103.21.244.0/22',   // Cloudflare
        '103.22.200.0/22',   // Cloudflare
        '172.64.0.0/13',     // Cloudflare
        // Add your load balancer IPs here
    ]);

// ============================================================================
// 8. CREATE WAF WITH ALL INTEGRATIONS
// ============================================================================
$waf = new WafMiddleware($config, $storage);
$waf->setLogger($logger);
$waf->setGeoIPService($geoipService);
$waf->setMetricsCollector($metrics);
$waf->setWebhookNotifier($webhooks);

// ============================================================================
// 9. PROCESS REQUEST
// ============================================================================
$startTime = microtime(true);
$allowed = $waf->handle($_SERVER);
$processingTime = (microtime(true) - $startTime) * 1000;

// Log performance
$metrics->timing('waf.processing_time', $processingTime);

if (!$allowed) {
    $reason = $waf->getBlockReason();
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Log blocked request
    $logger->warning('Request blocked', [
        'ip' => $clientIP,
        'reason' => $reason,
        'path' => $_SERVER['REQUEST_URI'] ?? '/',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
    ]);

    // Increment block metrics
    $metrics->increment('waf.requests.blocked');
    $metrics->increment("waf.blocked.{$reason}");

    // Send HTTP 403 response
    http_response_code(403);
    header('Content-Type: application/json');

    echo json_encode([
        'error' => 'Access Denied',
        'reason' => $reason,
        'message' => 'Your request has been blocked for security reasons.',
        'request_id' => uniqid('req_', true),
        'timestamp' => time(),
    ], JSON_PRETTY_PRINT);

    exit;
}

// ============================================================================
// 10. REQUEST ALLOWED - CONTINUE TO APPLICATION
// ============================================================================
$metrics->increment('waf.requests.allowed');

// Optional: Get GeoIP data for logging/analytics
$clientIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$geoData = $geoipService->lookup($clientIP);

if ($geoData) {
    $logger->info('Request allowed', [
        'ip' => $clientIP,
        'country' => $geoData['country'],
        'city' => $geoData['city'],
        'is_proxy' => $geoData['is_proxy'],
        'is_datacenter' => $geoData['is_datacenter'],
        'processing_time_ms' => round($processingTime, 2),
    ]);
}

// Your application continues here...
echo "✅ Request passed all security checks\n";
echo "Processing time: " . round($processingTime, 2) . "ms\n";

if ($geoData) {
    echo "Location: {$geoData['city']}, {$geoData['country_name']}\n";
}
