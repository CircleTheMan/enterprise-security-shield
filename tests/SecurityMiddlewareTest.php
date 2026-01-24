<?php
/**
 * Security Middleware - COMPREHENSIVE TESTS
 *
 * Tests all security components with REAL storage backends.
 * NO MOCKS. NO FAKE DATA. REAL PostgreSQL + Redis.
 *
 * REQUIREMENTS:
 * 1. PostgreSQL running (docker/OrbStack)
 * 2. Redis running
 * 3. Run: psql -U postgres -f tests/setup-test-db.sql
 */

require __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Storage\DatabaseStorage;
use Senza1dio\SecurityShield\Storage\NullStorage;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Services\WebhookNotifier;
use Senza1dio\SecurityShield\Services\GeoIP\GeoIPService;
use Senza1dio\SecurityShield\Utils\IPUtils;

// Test counter
$tests_passed = 0;
$tests_failed = 0;
$tests_total = 0;

function test(string $name, callable $test): void {
    global $tests_passed, $tests_failed, $tests_total;
    $tests_total++;

    try {
        $result = $test();
        if ($result === true) {
            echo "  [PASS] $name\n";
            $tests_passed++;
        } else {
            echo "  [FAIL] $name\n";
            $tests_failed++;
        }
    } catch (Throwable $e) {
        echo "  [ERROR] $name - {$e->getMessage()}\n";
        $tests_failed++;
    }
}

function section(string $title): void {
    echo "\n=== $title ===\n";
}

// ============================================================================
// SETUP
// ============================================================================

echo "SECURITY MIDDLEWARE - COMPREHENSIVE TEST SUITE\n";
echo "================================================\n\n";

// Connect to databases
try {
    $pdo = new PDO(
        'pgsql:host=localhost;port=5432;dbname=security_shield_test',
        'shield_test_user',
        'test_password_123'
    );
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "[OK] PostgreSQL connected\n";
} catch (PDOException $e) {
    echo "[FATAL] PostgreSQL connection failed: {$e->getMessage()}\n";
    echo "Run: psql -U postgres -f tests/setup-test-db.sql\n";
    exit(1);
}

try {
    $redis = new Redis();
    $redis->connect('localhost', 6379);
    $redis->ping();
    echo "[OK] Redis connected\n";
} catch (RedisException $e) {
    echo "[FATAL] Redis connection failed: {$e->getMessage()}\n";
    exit(1);
}

// Clean test data
$pdo->exec("DELETE FROM security_events WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM ip_bans WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM ip_scores WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM request_counts WHERE ip LIKE '198.51.100.%'");
$redis->flushDb();
echo "[OK] Test data cleaned\n";

$storage = new DatabaseStorage($pdo, $redis, 'test_');

// ============================================================================
// 1. USER-AGENT BYPASS PREVENTION
// ============================================================================

section("1. USER-AGENT BYPASS PREVENTION");

test("Empty User-Agent triggers instant ban (100 points)", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $middleware = new SecurityMiddleware($config);

    $server = [
        'REMOTE_ADDR' => '198.51.100.1',
        'REQUEST_URI' => '/',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => '', // Empty
    ];

    $allowed = $middleware->handle($server);

    // Should be BLOCKED (100 points > 50 threshold)
    return $allowed === false;
});

test("Space-only User-Agent triggers instant ban (bypass attempt)", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $middleware = new SecurityMiddleware($config);

    $server = [
        'REMOTE_ADDR' => '198.51.100.2',
        'REQUEST_URI' => '/',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => '   ', // Spaces only - bypass attempt
    ];

    $allowed = $middleware->handle($server);

    // Should be BLOCKED (trim makes it empty = 100 points)
    return $allowed === false;
});

test("Tab/newline User-Agent triggers instant ban", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $middleware = new SecurityMiddleware($config);

    $server = [
        'REMOTE_ADDR' => '198.51.100.3',
        'REQUEST_URI' => '/',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => "\t\n\r", // Whitespace only
    ];

    $allowed = $middleware->handle($server);

    return $allowed === false;
});

// ============================================================================
// 2. PATH TRAVERSAL PREVENTION (HONEYPOT)
// ============================================================================

section("2. PATH TRAVERSAL PREVENTION (HONEYPOT)");

test("Direct .env access triggers honeypot", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->enableHoneypot(true);

    $honeypot = new HoneypotMiddleware($config);

    // isHoneypotPath expects a string path, not $_SERVER array
    $isHoneypot = $honeypot->isHoneypotPath('/.env');
    return $isHoneypot === true;
});

test("Path traversal /../.env is normalized and detected", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->enableHoneypot(true);

    $honeypot = new HoneypotMiddleware($config);

    // Traversal attempt - should be normalized and detected
    $isHoneypot = $honeypot->isHoneypotPath('/foo/../.env');
    return $isHoneypot === true;
});

test("Double-encoded path traversal is detected", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->enableHoneypot(true);

    $honeypot = new HoneypotMiddleware($config);

    // URL-encoded ../ should be decoded and detected
    $isHoneypot = $honeypot->isHoneypotPath('/%2e%2e/%2e%2e/.env');
    return $isHoneypot === true;
});

test("Case variation wp-CONFIG.php is detected", function() use ($storage) {
    $storage->clear();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->enableHoneypot(true);

    $honeypot = new HoneypotMiddleware($config);

    // Case variation should be normalized and detected
    $isHoneypot = $honeypot->isHoneypotPath('/WP-CONFIG.PHP');
    return $isHoneypot === true;
});

// ============================================================================
// 3. IP UTILITIES
// ============================================================================

section("3. IP UTILITIES");

test("isPrivateIP detects 10.x.x.x range", function() {
    return IPUtils::isPrivateIP('10.0.0.1') === true;
});

test("isPrivateIP detects 172.16.x.x range", function() {
    return IPUtils::isPrivateIP('172.16.0.1') === true;
});

test("isPrivateIP detects 192.168.x.x range", function() {
    return IPUtils::isPrivateIP('192.168.1.1') === true;
});

test("isPrivateIP detects 127.0.0.1 loopback", function() {
    return IPUtils::isPrivateIP('127.0.0.1') === true;
});

test("isPrivateIP rejects public IP 8.8.8.8", function() {
    return IPUtils::isPrivateIP('8.8.8.8') === false;
});

test("isInCIDR matches 192.168.1.50 in 192.168.1.0/24", function() {
    return IPUtils::isInCIDR('192.168.1.50', '192.168.1.0/24') === true;
});

test("isInCIDR rejects 192.168.2.1 from 192.168.1.0/24", function() {
    return IPUtils::isInCIDR('192.168.2.1', '192.168.1.0/24') === false;
});

test("extractClientIP uses X-Forwarded-For with trusted proxy", function() {
    $server = [
        'REMOTE_ADDR' => '10.0.0.1', // Internal proxy
        'HTTP_X_FORWARDED_FOR' => '203.0.113.50, 10.0.0.1',
    ];
    $trustedProxies = ['10.0.0.0/8'];

    $clientIP = IPUtils::extractClientIP($server, $trustedProxies);
    return $clientIP === '203.0.113.50';
});

test("extractClientIP ignores X-Forwarded-For from untrusted proxy", function() {
    $server = [
        'REMOTE_ADDR' => '203.0.113.99', // Public IP (not trusted)
        'HTTP_X_FORWARDED_FOR' => '10.0.0.1', // Spoofed
    ];
    $trustedProxies = ['10.0.0.0/8']; // Only trust internal

    $clientIP = IPUtils::extractClientIP($server, $trustedProxies);
    // Should return REMOTE_ADDR, not spoofed header
    return $clientIP === '203.0.113.99';
});

// ============================================================================
// 4. WEBHOOK SECURITY
// ============================================================================

section("4. WEBHOOK SECURITY");

test("WebhookNotifier rejects HTTP (requires HTTPS)", function() {
    $notifier = new WebhookNotifier();

    try {
        $notifier->addWebhook('insecure', 'http://example.com/webhook');
        return false; // Should have thrown
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'HTTPS');
    }
});

test("WebhookNotifier rejects localhost", function() {
    $notifier = new WebhookNotifier();

    try {
        $notifier->addWebhook('local', 'https://localhost/webhook');
        return false;
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'localhost');
    }
});

test("WebhookNotifier rejects 127.0.0.1", function() {
    $notifier = new WebhookNotifier();

    try {
        $notifier->addWebhook('loopback', 'https://127.0.0.1/webhook');
        return false;
    } catch (InvalidArgumentException $e) {
        return true;
    }
});

test("WebhookNotifier rejects private IP 10.0.0.1", function() {
    $notifier = new WebhookNotifier();

    try {
        $notifier->addWebhook('internal', 'https://10.0.0.1/webhook');
        return false;
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'private');
    }
});

test("WebhookNotifier accepts valid HTTPS URL", function() {
    $notifier = new WebhookNotifier();

    try {
        $notifier->addWebhook('valid', 'https://hooks.slack.com/services/xxx');
        return true;
    } catch (InvalidArgumentException $e) {
        return false;
    }
});

// ============================================================================
// 5. GEOIP VALIDATION
// ============================================================================

section("5. GEOIP VALIDATION");

test("GeoIPService rejects invalid country code (too long)", function() use ($storage) {
    $geoip = new GeoIPService($storage);

    try {
        $geoip->isCountry('8.8.8.8', 'USAAA');
        return false;
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), '2 letters');
    }
});

test("GeoIPService rejects numeric country code", function() use ($storage) {
    $geoip = new GeoIPService($storage);

    try {
        $geoip->isCountry('8.8.8.8', '12');
        return false;
    } catch (InvalidArgumentException $e) {
        return true;
    }
});

test("GeoIPService accepts valid country code US", function() use ($storage) {
    $geoip = new GeoIPService($storage);

    try {
        // Should not throw (result depends on provider)
        $geoip->isCountry('8.8.8.8', 'US');
        return true;
    } catch (InvalidArgumentException $e) {
        return false;
    }
});

// ============================================================================
// 6. RATE LIMITING ACCURACY
// ============================================================================

section("6. RATE LIMITING ACCURACY");

test("Rate limit increments correctly (no lost counts)", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.50';
    $window = 60;

    // Increment 100 times
    for ($i = 0; $i < 100; $i++) {
        $storage->incrementRequestCount($testIP, $window, 'test_action');
    }

    $count = $storage->getRequestCount($testIP, $window, 'test_action');
    return $count === 100;
});

test("Rate limit separates actions correctly", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.51';
    $window = 60;

    // Increment different actions
    for ($i = 0; $i < 10; $i++) {
        $storage->incrementRequestCount($testIP, $window, 'action_a');
    }
    for ($i = 0; $i < 20; $i++) {
        $storage->incrementRequestCount($testIP, $window, 'action_b');
    }

    $countA = $storage->getRequestCount($testIP, $window, 'action_a');
    $countB = $storage->getRequestCount($testIP, $window, 'action_b');

    return $countA === 10 && $countB === 20;
});

// ============================================================================
// 7. SCORE ACCUMULATION
// ============================================================================

section("7. SCORE ACCUMULATION");

test("Score increments atomically", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.60';
    $ttl = 3600;

    // Multiple increments
    $storage->incrementScore($testIP, 10, $ttl);
    $storage->incrementScore($testIP, 20, $ttl);
    $storage->incrementScore($testIP, 30, $ttl);

    $score = $storage->getScore($testIP);
    return $score === 60;
});

test("Ban persists and blocks subsequent requests", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.61';

    $storage->banIP($testIP, 3600, 'test_ban');

    $isBanned = $storage->isBanned($testIP);
    $isBannedCached = $storage->isIpBannedCached($testIP);

    return $isBanned === true && $isBannedCached === true;
});

test("Unban removes ban status", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.62';

    $storage->banIP($testIP, 3600, 'test_ban');
    $storage->unbanIP($testIP);

    $isBanned = $storage->isBanned($testIP);
    return $isBanned === false;
});

// ============================================================================
// 8. SECURITY EVENT LOGGING
// ============================================================================

section("8. SECURITY EVENT LOGGING");

test("Security events are logged with correct data", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.70';

    $storage->logSecurityEvent('test_event', $testIP, [
        'reason' => 'unit_test',
        'score' => 100,
    ]);

    $events = $storage->getRecentEvents(10, 'test_event');

    if (count($events) === 0) {
        return false;
    }

    $event = $events[0];
    return $event['ip'] === $testIP && $event['type'] === 'test_event';
});

test("Duplicate events are deduplicated within time window", function() use ($storage) {
    $storage->clear();
    $testIP = '198.51.100.71';

    // Log same event twice quickly
    $storage->logSecurityEvent('dedup_test', $testIP, ['key' => 'value']);
    $storage->logSecurityEvent('dedup_test', $testIP, ['key' => 'value']);

    $events = $storage->getRecentEvents(100, 'dedup_test');

    // Should have only 1 event (deduplicated)
    return count($events) === 1;
});

// ============================================================================
// 9. NULL STORAGE (MEMORY) CONSISTENCY
// ============================================================================

section("9. NULL STORAGE (MEMORY) CONSISTENCY");

test("NullStorage maintains consistent state", function() {
    $nullStorage = new NullStorage();

    $nullStorage->setScore('test_ip', 50, 3600);
    $score = $nullStorage->getScore('test_ip');

    return $score === 50;
});

test("NullStorage clear() resets all data", function() {
    $nullStorage = new NullStorage();

    $nullStorage->setScore('test_ip', 50, 3600);
    $nullStorage->banIP('test_ip', 3600, 'test');
    $nullStorage->set('cache_key', 'value', 3600);

    $nullStorage->clear();

    $score = $nullStorage->getScore('test_ip');
    $isBanned = $nullStorage->isBanned('test_ip');
    $cached = $nullStorage->get('cache_key');

    return $score === null && $isBanned === false && $cached === null;
});

// ============================================================================
// CLEANUP AND RESULTS
// ============================================================================

echo "\n================================================\n";
echo "CLEANUP\n";
$pdo->exec("DELETE FROM security_events WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM ip_bans WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM ip_scores WHERE ip LIKE '198.51.100.%'");
$pdo->exec("DELETE FROM request_counts WHERE ip LIKE '198.51.100.%'");
$redis->flushDb();
echo "[OK] Test data cleaned\n";

echo "\n================================================\n";
echo "RESULTS\n";
echo "================================================\n";
echo "Total:  $tests_total\n";
echo "Passed: $tests_passed\n";
echo "Failed: $tests_failed\n";
echo "================================================\n";

if ($tests_failed > 0) {
    echo "\n[FAILED] Some tests did not pass!\n";
    exit(1);
} else {
    echo "\n[SUCCESS] All tests passed!\n";
    exit(0);
}
