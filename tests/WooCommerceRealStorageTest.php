<?php
/**
 * WooCommerce Security Middleware - REAL STORAGE TESTS
 *
 * Tests with REAL DatabaseStorage (PostgreSQL) to verify:
 * - Rate limiting actually works
 * - Score accumulation persists
 * - Bans are enforced
 * - WooCommerce-specific rate limits function correctly
 *
 * SETUP REQUIRED:
 * 1. PostgreSQL running (Docker/OrbStack)
 * 2. Run: psql -U postgres -f tests/setup-test-db.sql
 * 3. Database: security_shield_test
 * 4. User: shield_test_user / Password: test_password_123
 */

require __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Integrations\WooCommerce\WooCommerceSecurityMiddleware;
use Senza1dio\SecurityShield\Storage\DatabaseStorage;
use Senza1dio\SecurityShield\Config\SecurityConfig;

// Test counter
$tests_passed = 0;
$tests_failed = 0;

function test(string $name, callable $test): void {
    global $tests_passed, $tests_failed;

    try {
        $result = $test();
        if ($result) {
            echo "✅ PASS: $name\n";
            $tests_passed++;
        } else {
            echo "❌ FAIL: $name\n";
            $tests_failed++;
        }
    } catch (Exception $e) {
        echo "💥 ERROR: $name - {$e->getMessage()}\n";
        $tests_failed++;
    }
}

// ============================================================================
// DATABASE SETUP (OrbStack PostgreSQL)
// ============================================================================

echo "=== WooCommerce Security Middleware - REAL STORAGE TESTS ===\n\n";

// Connect to Test Database (PostgreSQL)
try {
    $pdo = new PDO(
        'pgsql:host=localhost;port=5432;dbname=security_shield_test',
        'shield_test_user',
        'test_password_123'
    );
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "✅ Connected to PostgreSQL test database\n";
} catch (PDOException $e) {
    echo "❌ CRITICAL: Cannot connect to PostgreSQL: {$e->getMessage()}\n";
    echo "   Setup instructions:\n";
    echo "   1. Start PostgreSQL (docker/OrbStack)\n";
    echo "   2. Run: psql -U postgres -f tests/setup-test-db.sql\n";
    echo "   3. Retry tests\n\n";
    exit(1);
}

// Connect to Redis (for full storage testing)
try {
    $redis = new Redis();
    $redis->connect('localhost', 6379);
    $redis->ping();
    echo "✅ Connected to Redis\n\n";
} catch (RedisException $e) {
    echo "❌ CRITICAL: Cannot connect to Redis: {$e->getMessage()}\n";
    echo "   Setup instructions:\n";
    echo "   1. Start Redis: docker run -d --name security_shield_redis -p 6379:6379 redis:7-alpine\n";
    echo "   2. Retry tests\n\n";
    exit(1);
}

// Create storage instance with BOTH PostgreSQL + Redis (production-like)
$storage = new DatabaseStorage($pdo, $redis, 'woocommerce_test_');

// Clean up test data before starting
echo "🧹 Cleaning up previous test data...\n";
$pdo->exec("DELETE FROM security_events WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM ip_bans WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM ip_scores WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM request_counts WHERE ip LIKE '192.0.2.%'");
$redis->flushDb(); // Clear all Redis test data
echo "✅ Test data cleaned\n\n";

// ============================================================================
// TEST 1: Rate Limiting - Checkout (5 requests per 5 minutes)
// ============================================================================

test("Rate limiting: Checkout allows 5 requests then blocks", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.10';

    // First 5 checkout requests should PASS
    for ($i = 1; $i <= 5; $i++) {
        $server = [
            'REMOTE_ADDR' => $testIp,
            'REQUEST_URI' => '/checkout/?wc-ajax=update_order_review',
            'REQUEST_METHOD' => 'POST',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ];

        $allowed = $wooSecurity->handle($server);
        if (!$allowed) {
            echo "  ❌ Request $i was blocked (should pass)\n";
            return false;
        }
    }

    // 6th checkout request should FAIL (rate limit exceeded)
    $server = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/checkout/?wc-ajax=update_order_review',
        'REQUEST_METHOD' => 'POST',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    $allowed = $wooSecurity->handle($server);
    if ($allowed) {
        echo "  ❌ 6th request was allowed (should be blocked)\n";
        return false;
    }

    return true; // 5 passed, 6th blocked = SUCCESS
});

// ============================================================================
// TEST 2: Rate Limiting - Add to Cart (30 requests per minute)
// ============================================================================

test("Rate limiting: Add to cart allows 30 requests then blocks", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.20';

    // First 30 add-to-cart requests should PASS
    for ($i = 1; $i <= 30; $i++) {
        $server = [
            'REMOTE_ADDR' => $testIp,
            'REQUEST_URI' => '/?add-to-cart=123',
            'REQUEST_METHOD' => 'GET',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ];

        $allowed = $wooSecurity->handle($server);
        if (!$allowed) {
            echo "  ❌ Request $i was blocked (should pass)\n";
            return false;
        }
    }

    // 31st request should FAIL (rate limit exceeded)
    $server = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/?add-to-cart=456',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    $allowed = $wooSecurity->handle($server);
    if ($allowed) {
        echo "  ❌ 31st request was allowed (should be blocked)\n";
        return false;
    }

    return true;
});

// ============================================================================
// TEST 3: Score Accumulation - Multiple Suspicious Paths
// ============================================================================

test("Score accumulation: Multiple suspicious paths lead to ban", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.30';

    // First request: /?author=1 (20 points - user enumeration)
    $server1 = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/?author=1',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];
    $wooSecurity->handle($server1); // 20 points (not banned yet)

    // Second request: /wp-json/wp/v2/users (20 points - user enumeration API)
    $server2 = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/wp-json/wp/v2/users',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];
    $wooSecurity->handle($server2); // 40 points total (not banned yet)

    // Third request: /wp-content/backup-db/ (20 points - backup scanner)
    $server3 = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/wp-content/backup-db/database.sql',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];
    $allowed = $wooSecurity->handle($server3); // 60 points total (BANNED!)

    // Should be BLOCKED now (60 >= 50 threshold)
    if ($allowed) {
        echo "  ❌ 3rd request passed (should be banned with 60 points)\n";
        return false;
    }

    return true;
});

// ============================================================================
// TEST 4: Ban Persistence - Banned IP stays banned
// ============================================================================

test("Ban persistence: Once banned, IP stays banned across requests", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.40';

    // Trigger instant ban with wp-config.php (50 points)
    $server1 = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/wp-config.php',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];
    $wooSecurity->handle($server1); // BANNED

    // Now try legitimate request - should still be BLOCKED
    $server2 = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/shop/product/test',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];
    $allowed = $wooSecurity->handle($server2);

    if ($allowed) {
        echo "  ❌ Banned IP was allowed for legitimate request\n";
        return false;
    }

    return true;
});

// ============================================================================
// TEST 5: Whitelist Bypass with Real Storage
// ============================================================================

test("Whitelist bypass: Whitelisted IP passes even with suspicious paths", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->addIPWhitelist('192.0.2.50');

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Multiple suspicious requests from whitelisted IP
    $testIp = '192.0.2.50';

    $suspiciousPaths = [
        '/wp-admin/admin-ajax.php',
        '/wp-json/wc/v3/products',
        '/wp-config.php',
        '/?author=1',
    ];

    foreach ($suspiciousPaths as $path) {
        $server = [
            'REMOTE_ADDR' => $testIp,
            'REQUEST_URI' => $path,
            'REQUEST_METHOD' => 'GET',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ];

        $allowed = $wooSecurity->handle($server);
        if (!$allowed) {
            echo "  ❌ Whitelisted IP was blocked for $path\n";
            return false;
        }
    }

    return true;
});

// ============================================================================
// TEST 6: Coupon Brute Force Protection (10 per 5 minutes)
// ============================================================================

test("Rate limiting: Coupon checks allow 10 requests then block", function() use ($storage) {
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.60';

    // First 10 coupon checks should PASS
    for ($i = 1; $i <= 10; $i++) {
        $server = [
            'REMOTE_ADDR' => $testIp,
            'REQUEST_URI' => '/?wc-ajax=apply_coupon',
            'REQUEST_METHOD' => 'POST',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ];

        $allowed = $wooSecurity->handle($server);
        if (!$allowed) {
            echo "  ❌ Coupon check $i was blocked (should pass)\n";
            return false;
        }
    }

    // 11th coupon check should FAIL
    $server = [
        'REMOTE_ADDR' => $testIp,
        'REQUEST_URI' => '/?wc-ajax=apply_coupon',
        'REQUEST_METHOD' => 'POST',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    $allowed = $wooSecurity->handle($server);
    if ($allowed) {
        echo "  ❌ 11th coupon check was allowed (should be blocked)\n";
        return false;
    }

    return true;
});

// ============================================================================
// TEST 7: Framework Detection - WordPress Admin NOT Banned (CRITICAL!)
// ============================================================================

test("Framework detection: WordPress admin paths are NOT honeypot (if WordPress detected)", function() use ($storage) {
    // Simulate WordPress environment
    define('ABSPATH', '/var/www/html/');

    // Force framework detection reset
    \Senza1dio\SecurityShield\Services\FrameworkDetector::reset();

    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->enableHoneypot(true); // Honeypot ENABLED!

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    $testIp = '192.0.2.100'; // NOT whitelisted

    // Access WordPress admin paths (should be ALLOWED if WordPress detected)
    $wordpressPaths = [
        '/wp-admin/',
        '/wp-admin/index.php',
        '/wp-login.php',
        '/wp-json/wc/v3/products',
    ];

    foreach ($wordpressPaths as $path) {
        $server = [
            'REMOTE_ADDR' => $testIp,
            'REQUEST_URI' => $path,
            'REQUEST_METHOD' => 'GET',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ];

        // Note: This test verifies that /wp-admin/ doesn't trigger honeypot scoring
        // It may still be subject to rate limiting, which is correct behavior
        $wooSecurity->handle($server);
    }

    // After accessing multiple WordPress admin paths, IP should NOT be banned
    // (Framework detection should have excluded these from honeypot)
    $score = $storage->getScore($testIp);

    // Score should be low (no honeypot points added)
    // If framework detection works, score should be 0 or minimal
    if ($score >= 50) {
        echo "  ❌ WordPress admin got banned (score: $score) - Framework detection FAILED!\n";
        return false;
    }

    return true;
});

// ============================================================================
// CLEANUP AND RESULTS
// ============================================================================

echo "\n🧹 Cleaning up test data...\n";
$pdo->exec("DELETE FROM security_events WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM ip_bans WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM ip_scores WHERE ip LIKE '192.0.2.%'");
$pdo->exec("DELETE FROM request_counts WHERE ip LIKE '192.0.2.%'");
$redis->flushDb(); // Clear all Redis test data
echo "✅ Test data cleaned\n\n";

echo "=== Test Results ===\n";
echo "Passed: $tests_passed\n";
echo "Failed: $tests_failed\n";

if ($tests_failed > 0) {
    echo "\n❌ TESTS FAILED - WooCommerce integration has BUGS!\n";
    exit(1);
} else {
    echo "\n✅ ALL TESTS PASSED - WooCommerce integration is SOLID!\n";
    exit(0);
}
