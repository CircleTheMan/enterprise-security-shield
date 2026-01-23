<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Services\Metrics\RedisMetricsCollector;

/**
 * Example 3: Metrics Collection & Monitoring
 *
 * Track security events and performance metrics.
 * Useful for:
 * - Dashboards (Grafana, Datadog)
 * - Alerting (PagerDuty, Slack)
 * - Capacity planning
 * - Attack pattern analysis
 */

// 1. Setup Redis and storage
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$storage = new RedisStorage($redis, 'security_shield:');

// 2. Setup metrics collector
$metrics = new RedisMetricsCollector($redis, 'security_metrics:');

// 3. Configure security
$config = new SecurityConfig();
$config
    ->setEnabled(true)
    ->setAutoBlockThreshold(100);

// 4. Create WAF with metrics
$waf = new WafMiddleware($config, $storage);
$waf->setMetricsCollector($metrics);

// 5. Process request (metrics are collected automatically)
$startTime = microtime(true);
$allowed = $waf->handle($_SERVER);
$processingTime = (microtime(true) - $startTime) * 1000; // Convert to milliseconds

// Record additional metrics
$metrics->timing('waf.processing_time', $processingTime);

if ($allowed) {
    $metrics->increment('waf.requests.allowed');
    echo "✅ Request allowed\n";
} else {
    $metrics->increment('waf.requests.blocked');
    $reason = $waf->getBlockReason();
    $metrics->increment("waf.blocked.{$reason}");
    echo "❌ Request blocked: {$reason}\n";
}

// 6. View collected metrics (for dashboard/monitoring)
echo "\n📊 Current Security Metrics:\n";
echo "----------------------------\n";

$allMetrics = $metrics->getAll();
foreach ($allMetrics as $metric => $value) {
    echo sprintf("%-40s %10.2f\n", $metric, $value);
}

// 7. Example: Calculate block rate
$totalRequests = ($metrics->get('waf.requests.allowed') ?? 0) + ($metrics->get('waf.requests.blocked') ?? 0);
$blockedRequests = $metrics->get('waf.requests.blocked') ?? 0;
$blockRate = $totalRequests > 0 ? ($blockedRequests / $totalRequests) * 100 : 0;

echo "\n📈 Statistics:\n";
echo "Total Requests: " . (int) $totalRequests . "\n";
echo "Blocked Requests: " . (int) $blockedRequests . "\n";
echo "Block Rate: " . number_format($blockRate, 2) . "%\n";

if ($blockRate > 10) {
    echo "⚠️  WARNING: High block rate detected! Possible attack in progress.\n";
}

// 8. Example: Track response time histogram
$p50 = 50.5; // Calculate p50 from histogram (simplified)
$p95 = 125.3; // Calculate p95 from histogram
$p99 = 250.7; // Calculate p99 from histogram

echo "\n⏱️  Response Time Percentiles:\n";
echo "p50: " . number_format($p50, 2) . "ms\n";
echo "p95: " . number_format($p95, 2) . "ms\n";
echo "p99: " . number_format($p99, 2) . "ms\n";
