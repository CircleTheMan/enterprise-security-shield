<?php
/**
 * WooCommerce Security Middleware - SERIOUS TESTS
 *
 * Tests EVERY scenario to ensure no bugs before commit.
 */

require __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Integrations\WooCommerce\WooCommerceSecurityMiddleware;
use Senza1dio\SecurityShield\Storage\NullStorage;
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

echo "=== WooCommerce Security Middleware Tests ===\n\n";

// ============================================================================
// TEST 1: Whitelist Bypass
// ============================================================================

test("Whitelist IP bypasses ALL checks (including WooCommerce paths)", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->addIPWhitelist('127.0.0.1'); // Whitelist test IP

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate suspicious WooCommerce request from whitelisted IP
    $server = [
        'REMOTE_ADDR' => '127.0.0.1',
        'REQUEST_URI' => '/wp-admin/admin-ajax.php', // Suspicious path
        'REQUEST_METHOD' => 'POST',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should ALLOW because IP is whitelisted
    $allowed = $wooSecurity->handle($server);

    return $allowed === true; // MUST be true
});

// ============================================================================
// TEST 2: Non-Whitelisted IP Gets Scored
// ============================================================================

test("Non-whitelisted IP accessing suspicious path gets scored", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate suspicious request from non-whitelisted IP
    $server = [
        'REMOTE_ADDR' => '192.0.2.100', // NOT whitelisted
        'REQUEST_URI' => '/wp-admin/admin-ajax.php',
        'REQUEST_METHOD' => 'POST',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should BLOCK because path is suspicious and IP NOT whitelisted
    $allowed = $wooSecurity->handle($server);

    return $allowed === false; // MUST be false
});

// ============================================================================
// TEST 3: Legitimate Request is Allowed
// ============================================================================

test("Legitimate request (not suspicious path) is allowed", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate legitimate request
    $server = [
        'REMOTE_ADDR' => '192.0.2.100',
        'REQUEST_URI' => '/shop/product/test-product', // Legitimate path
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should ALLOW because path is NOT suspicious
    $allowed = $wooSecurity->handle($server);

    return $allowed === true; // MUST be true
});

// ============================================================================
// TEST 4: wp-config.php Access Gets High Score
// ============================================================================

test("wp-config.php access gets critical score (50 points = instant ban)", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50) // Ban at 50 points
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate wp-config.php access (CRITICAL)
    $server = [
        'REMOTE_ADDR' => '192.0.2.100',
        'REQUEST_URI' => '/wp-config.php', // CRITICAL path
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should BLOCK immediately (score 50 = instant ban)
    $allowed = $wooSecurity->handle($server);

    return $allowed === false; // MUST be false
});

// ============================================================================
// TEST 5: WooCommerce REST API Path Detection
// ============================================================================

test("WooCommerce REST API path is detected as suspicious", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate WooCommerce API request
    $server = [
        'REMOTE_ADDR' => '192.0.2.100',
        'REQUEST_URI' => '/wp-json/wc/v3/products',
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should BLOCK (API brute force attempt)
    $allowed = $wooSecurity->handle($server);

    return $allowed === false; // MUST be false
});

// ============================================================================
// TEST 6: Parent WAF Checks Still Work
// ============================================================================

test("Parent WAF scanner detection still works", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger());

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // Simulate NULL User-Agent (instant ban - 100 points)
    $server = [
        'REMOTE_ADDR' => '192.0.2.100',
        'REQUEST_URI' => '/shop/', // Normal path
        'REQUEST_METHOD' => 'GET',
        'HTTP_USER_AGENT' => '', // NULL/empty UA = instant ban
    ];

    // Should BLOCK (NULL user agent detected by parent WAF)
    $allowed = $wooSecurity->handle($server);

    return $allowed === false; // MUST be false
});

// ============================================================================
// TEST 7: CIDR Whitelist Works
// ============================================================================

test("CIDR range whitelist works correctly", function() {
    $storage = new NullStorage();
    $config = new SecurityConfig();
    $config->setScoreThreshold(50)
           ->setStorage($storage)
           ->setLogger(new \Senza1dio\SecurityShield\Storage\NullLogger())
           ->addIPWhitelist('192.0.2.0/24'); // Whitelist entire subnet

    $wooSecurity = new WooCommerceSecurityMiddleware($config);

    // IP in whitelisted CIDR range
    $server = [
        'REMOTE_ADDR' => '192.0.2.50', // In 192.0.2.0/24
        'REQUEST_URI' => '/wp-admin/admin-ajax.php',
        'REQUEST_METHOD' => 'POST',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
    ];

    // Should ALLOW (IP in whitelisted CIDR)
    $allowed = $wooSecurity->handle($server);

    return $allowed === true; // MUST be true
});

// ============================================================================
// RESULTS
// ============================================================================

echo "\n=== Test Results ===\n";
echo "Passed: $tests_passed\n";
echo "Failed: $tests_failed\n";

if ($tests_failed > 0) {
    echo "\n❌ TESTS FAILED - DO NOT COMMIT!\n";
    exit(1);
} else {
    echo "\n✅ ALL TESTS PASSED - Safe to commit!\n";
    exit(0);
}
