<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Services\WebhookNotifier;

/**
 * Example 4: Real-Time Webhook Alerts
 *
 * Send instant notifications to Slack, Discord, or custom endpoints.
 * Useful for:
 * - Real-time security monitoring
 * - Incident response
 * - Team notifications
 * - Security operations center (SOC)
 */

// 1. Setup Redis and storage
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$storage = new RedisStorage($redis, 'security_shield:');

// 2. Setup webhook notifier
$webhooks = new WebhookNotifier();
$webhooks
    ->addWebhook('slack', 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK')
    ->addWebhook('discord', 'https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK')
    ->addWebhook('custom', 'https://your-api.com/security-events')
    ->setTimeout(3)   // 3 second timeout
    ->setAsync(true); // Non-blocking (recommended)

// 3. Configure security
$config = new SecurityConfig();
$config
    ->setEnabled(true)
    ->setAutoBlockThreshold(100)
    ->setBanDuration(3600);

// 4. Create WAF with webhooks
$waf = new WafMiddleware($config, $storage);
$waf->setWebhookNotifier($webhooks);

// 5. Process request (webhooks are sent automatically on critical events)
$allowed = $waf->handle($_SERVER);

if (!$allowed) {
    $reason = $waf->getBlockReason();
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Webhook was already sent by WAF for auto-ban events
    // You can send additional custom webhooks:

    if ($reason === 'sql_injection') {
        $webhooks->notify('critical_attack', [
            'type' => 'SQL Injection',
            'ip' => $clientIP,
            'path' => $_SERVER['REQUEST_URI'] ?? '/',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'severity' => 'CRITICAL',
            'timestamp' => time(),
        ]);

        echo "🚨 CRITICAL: SQL injection attack detected and reported!\n";
    } elseif ($reason === 'honeypot_access') {
        $webhooks->notify('honeypot_triggered', [
            'ip' => $clientIP,
            'path' => $_SERVER['REQUEST_URI'] ?? '/',
            'severity' => 'HIGH',
            'timestamp' => time(),
        ]);

        echo "⚠️  HIGH: Honeypot trap triggered!\n";
    } else {
        echo "❌ Request blocked: {$reason}\n";
    }

    http_response_code(403);
    exit;
}

// 6. Example: Manual webhook for custom events
$webhooks->notify('user_action', [
    'action' => 'admin_login',
    'user' => 'admin@example.com',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
    'timestamp' => time(),
    'success' => true,
]);

echo "✅ Request allowed and logged\n";

/**
 * Slack Webhook Payload Example:
 * {
 *   "event": "critical_attack",
 *   "timestamp": 1706000000,
 *   "data": {
 *     "type": "SQL Injection",
 *     "ip": "203.0.113.50",
 *     "path": "/admin.php?id=1' OR '1'='1",
 *     "user_agent": "Mozilla/5.0...",
 *     "severity": "CRITICAL"
 *   }
 * }
 *
 * Discord Webhook: Same JSON structure
 * Custom Webhook: Same JSON structure (you can parse it on your server)
 */
