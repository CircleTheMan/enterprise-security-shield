<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;

/**
 * Example 1: Basic WAF Setup
 *
 * Minimal setup to get started with enterprise-security-shield.
 * Protects against SQL injection, XSS, path traversal, and common attacks.
 */

// 1. Connect to Redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('your-redis-password'); // If authentication is enabled

// 2. Create storage backend
$storage = new RedisStorage($redis, 'security_shield:');

// 3. Configure security rules
$config = new SecurityConfig();
$config
    ->setEnabled(true)
    ->setBanDuration(3600) // 1 hour ban
    ->setScoreTTL(900)      // 15 minutes score retention
    ->setAutoBlockThreshold(100) // Block after 100 points
    ->setBlockedResponseCode(403);

// 4. Create WAF middleware
$waf = new WafMiddleware($config, $storage);

// 5. Process incoming request
$allowed = $waf->handle($_SERVER);

if (!$allowed) {
    $reason = $waf->getBlockReason();
    http_response_code(403);

    echo json_encode([
        'error' => 'Access Denied',
        'reason' => $reason,
        'message' => 'Your request has been blocked for security reasons.',
    ]);
    exit;
}

// Request is clean - continue to your application
echo "✅ Request passed security checks!\n";
echo "You can now proceed with your application logic.\n";
