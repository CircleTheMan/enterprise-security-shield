<?php
/**
 * WooCommerce Security Integration Example
 *
 * This example shows how to integrate Enterprise Security Shield
 * with a WooCommerce-powered WordPress site.
 *
 * PROTECTS AGAINST:
 * - Admin AJAX abuse
 * - WooCommerce REST API brute force
 * - Payment gateway callback spoofing
 * - Cart manipulation
 * - Coupon brute force
 * - Account enumeration
 * - Checkout spam
 */

require __DIR__ . '/../vendor/autoload.php';

use Senza1dio\SecurityShield\Integrations\WooCommerce\WooCommerceSecurityMiddleware;
use Senza1dio\SecurityShield\Storage\RedisStorage;
use Senza1dio\SecurityShield\Config\SecurityConfig;

// ============================================================================
// BASIC SETUP (30 seconds)
// ============================================================================

// 1. Connect Redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
// $redis->auth('your_redis_password'); // If Redis has auth

// 2. Create storage
$storage = new RedisStorage($redis, 'woocommerce_security:');

// 3. Configure security
$config = new SecurityConfig();
$config->setScoreThreshold(50)          // Ban at 50 points
       ->setBanDuration(3600)                // 1 hour ban
       ->setScoreTTL(1800)                   // Scores expire after 30 minutes

       // CRITICAL: Whitelist your own IP to prevent self-ban!
       ->addWhitelist('YOUR_OFFICE_IP');     // Replace with your real IP

// 4. Create WooCommerce security middleware
$wooSecurity = new WooCommerceSecurityMiddleware($storage, $config);

// 5. Protect your site
if (!$wooSecurity->handle($_SERVER)) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Access Denied',
        'message' => 'Your request has been blocked for security reasons.',
    ]);
    exit;
}

// ============================================================================
// ENTERPRISE SETUP (Production-ready)
// ============================================================================

// Advanced configuration
$config
    // Threat scoring
    ->setScoreThreshold(100)           // More lenient threshold
    ->setBanDuration(7200)                 // 2 hours ban
    ->setScoreTTL(3600)                    // 1 hour score window

    // IP whitelist (your office, payment gateways)
    ->addWhitelist('203.0.113.1')         // Your office IP
    ->addWhitelist('192.0.2.0/24')        // Payment gateway IP range

    // IP blacklist (known attackers)
    ->addBlacklist('198.51.100.50')

    // Geo-blocking (optional - requires GeoIP)
    ->setGeoIPEnabled(true)
    ->setBlockedCountries(['CN', 'RU']);   // Block countries (if needed)

// Create middleware with full config
$wooSecurity = new WooCommerceSecurityMiddleware($storage, $config);

// Handle request
if (!$wooSecurity->handle($_SERVER)) {
    // Log to your logging system
    error_log(sprintf(
        '[WooCommerce Security] Blocked request from %s to %s',
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['REQUEST_URI'] ?? 'unknown'
    ));

    // Return JSON error (if AJAX request)
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => 'Security check failed',
        ]);
        exit;
    }

    // Return HTML error (if browser request)
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Access Denied</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #d32f2f; }
        </style>
    </head>
    <body>
        <h1>Access Denied</h1>
        <p>Your request has been blocked for security reasons.</p>
        <p>If you believe this is an error, please contact support.</p>
    </body>
    </html>
    <?php
    exit;
}

// ============================================================================
// WORDPRESS INTEGRATION (mu-plugin)
// ============================================================================

/*
 * Create file: wp-content/mu-plugins/woocommerce-security.php
 *
 * <?php
 * // WooCommerce Security Shield
 *
 * require_once __DIR__ . '/../../vendor/autoload.php';
 *
 * use Senza1dio\SecurityShield\Integrations\WooCommerce\WooCommerceSecurityMiddleware;
 * use Senza1dio\SecurityShield\Storage\RedisStorage;
 * use Senza1dio\SecurityShield\Config\SecurityConfig;
 *
 * // Setup (runs on every request)
 * add_action('init', function() {
 *     // Connect Redis
 *     $redis = new Redis();
 *     $redis->connect('127.0.0.1', 6379);
 *
 *     // Create storage
 *     $storage = new RedisStorage($redis, 'woocommerce_security:');
 *
 *     // Configure
 *     $config = new SecurityConfig();
 *     $config->setScoreThreshold(50)->setBanDuration(3600);
 *
 *     // Create middleware
 *     $wooSecurity = new WooCommerceSecurityMiddleware($storage, $config);
 *
 *     // Check request
 *     if (!$wooSecurity->handle($_SERVER)) {
 *         wp_die('Access Denied', 'Security', ['response' => 403]);
 *     }
 * }, 1); // Priority 1 = runs very early
 */

// ============================================================================
// SECURITY RECOMMENDATIONS
// ============================================================================

// Display security recommendations
$recommendations = WooCommerceSecurityMiddleware::getSecurityRecommendations();

echo "\n\n=== WooCommerce Security Recommendations ===\n\n";
foreach ($recommendations as $category => $recommendation) {
    echo sprintf("• %s: %s\n", strtoupper(str_replace('_', ' ', $category)), $recommendation);
}

// ============================================================================
// ADDITIONAL PROTECTIONS (Beyond this middleware)
// ============================================================================

/*
 * 1. Server-side cart validation (CRITICAL)
 *    - NEVER trust cart totals from client
 *    - Always recalculate prices server-side
 *    - Validate product availability and stock
 *
 * 2. Payment gateway signature validation
 *    - Use gateway SDK for signature verification
 *    - Never trust payment callbacks without signature check
 *    - Log all payment callbacks for audit
 *
 * 3. Coupon security
 *    - Implement CAPTCHA on coupon field
 *    - Rate limit coupon checks (handled by this middleware)
 *    - Log coupon usage for fraud detection
 *
 * 4. Admin security
 *    - Use strong passwords + 2FA
 *    - Limit login attempts (use plugin like Wordfence)
 *    - Restrict admin-ajax.php to authenticated users only
 *
 * 5. SSL/TLS
 *    - ALWAYS use HTTPS for checkout
 *    - Enable HSTS header
 *    - Use strong cipher suites
 *
 * 6. Regular updates
 *    - Keep WordPress + WooCommerce + plugins updated
 *    - Subscribe to security mailing lists
 *    - Test updates on staging first
 */

echo "\n\n=== Additional Security Notes ===\n";
echo "• This middleware blocks KNOWN attack patterns\n";
echo "• It does NOT replace proper input validation\n";
echo "• It does NOT validate payment gateway signatures\n";
echo "• It does NOT prevent business logic exploits\n";
echo "\n";
echo "For production use:\n";
echo "1. Combine with proper input validation\n";
echo "2. Use payment gateway SDKs for signature validation\n";
echo "3. Implement server-side cart validation\n";
echo "4. Enable SSL/TLS with HSTS\n";
echo "5. Keep WordPress + WooCommerce updated\n";
echo "\n";
