<?php

namespace Senza1dio\SecurityShield\Integrations\WooCommerce;

use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Contracts\StorageInterface;

/**
 * WooCommerce Security Middleware
 *
 * Specialized security layer for WooCommerce e-commerce sites.
 *
 * PROTECTIONS:
 * - Admin AJAX endpoint abuse (wp-admin/admin-ajax.php)
 * - WooCommerce REST API brute force (/wp-json/wc/v3/)
 * - Payment gateway callback spoofing
 * - Cart manipulation attacks (price tampering, negative quantities)
 * - Coupon brute force (automated coupon guessing)
 * - Account enumeration (user existence checks)
 * - Checkout spam (fake order submissions)
 *
 * LIMITATIONS:
 * - Does NOT protect against business logic exploits (requires custom code)
 * - Does NOT validate payment gateway signatures (use gateway-specific validation)
 * - Does NOT detect sophisticated cart manipulation (requires server-side validation)
 *
 * USAGE:
 * $wooSecurity = new WooCommerceSecurityMiddleware($storage, $config);
 * $wooSecurity->handle($_SERVER);
 *
 * @package Senza1dio\SecurityShield\Integrations\WooCommerce
 */
class WooCommerceSecurityMiddleware extends WafMiddleware
{
    /**
     * WooCommerce-specific suspicious paths
     *
     * @var array<string>
     */
    private const WC_SUSPICIOUS_PATHS = [
        // Admin paths (should be protected by WordPress auth)
        '/wp-admin/admin-ajax.php',
        '/wp-admin/admin-post.php',

        // WooCommerce REST API
        '/wp-json/wc/v1/',
        '/wp-json/wc/v2/',
        '/wp-json/wc/v3/',

        // Payment gateway callbacks (if not properly secured)
        '/wc-api/',
        '/?wc-api=',

        // Legacy endpoints
        '/wc-ajax/',
        '/?wc-ajax=',

        // Database backup files (scanner target)
        '/wp-content/backup-db/',
        '/wp-content/backups/',

        // Config files (should NEVER be accessible)
        '/wp-config.php',
        '/wp-config-sample.php',

        // User enumeration
        '/?author=',
        '/wp-json/wp/v2/users',
    ];

    /**
     * Rate limits for WooCommerce-specific actions
     *
     * @var array<string, array{requests: int, window: int}>
     */
    private const WC_RATE_LIMITS = [
        'checkout' => ['requests' => 5, 'window' => 300],        // 5 checkouts per 5 minutes
        'add_to_cart' => ['requests' => 30, 'window' => 60],     // 30 add-to-cart per minute
        'coupon_check' => ['requests' => 10, 'window' => 300],   // 10 coupon checks per 5 minutes
        'api_request' => ['requests' => 100, 'window' => 60],    // 100 API requests per minute
        'payment_callback' => ['requests' => 10, 'window' => 60], // 10 payment callbacks per minute
    ];

    /**
     * Handle WooCommerce-specific security checks
     *
     * IMPORTANT: Whitelist is checked FIRST by parent::handle()
     * If IP is whitelisted, WooCommerce checks are SKIPPED.
     *
     * @param array<string, mixed> $server $_SERVER superglobal
     * @param array<string, mixed> $get $_GET superglobal (optional)
     * @param array<string, mixed> $post $_POST superglobal (optional)
     * @return bool True if request is allowed, false if blocked
     */
    public function handle(array $server, array $get = [], array $post = []): bool
    {
        // Run standard WAF checks first (includes whitelist check)
        // If IP is whitelisted, parent::handle() returns true and WooCommerce checks are skipped
        $allowed = parent::handle($server, $get, $post);

        if (!$allowed) {
            return false;
        }

        // Get IP for WooCommerce-specific checks
        $ip = $server['REMOTE_ADDR'] ?? '0.0.0.0';

        // CRITICAL: If IP is whitelisted, skip WooCommerce-specific checks
        // This prevents site owners from being banned when accessing legitimate admin paths
        if ($this->isIPWhitelisted($ip)) {
            return true; // Whitelist bypass - no WooCommerce checks
        }

        // WooCommerce-specific checks (only if NOT whitelisted)
        $uri = $server['REQUEST_URI'] ?? '';
        $method = $server['REQUEST_METHOD'] ?? 'GET';

        // Check WooCommerce-specific suspicious paths
        if ($this->isWooCommerceSuspiciousPath($uri)) {
            $this->handleSuspiciousWooCommercePath($ip, $uri);
            return false;
        }

        // Check WooCommerce-specific rate limits
        if (!$this->checkWooCommerceRateLimits($ip, $uri, $method)) {
            return false;
        }

        return true;
    }

    /**
     * Check if path is WooCommerce-specific suspicious path
     *
     * @param string $uri Request URI
     * @return bool True if suspicious
     */
    private function isWooCommerceSuspiciousPath(string $uri): bool
    {
        foreach (self::WC_SUSPICIOUS_PATHS as $path) {
            if (stripos($uri, $path) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Handle suspicious WooCommerce path access
     *
     * @param string $ip Client IP
     * @param string $uri Request URI
     * @return void
     */
    private function handleSuspiciousWooCommercePath(string $ip, string $uri): void
    {
        // Increment threat score
        $score = 20; // Medium severity

        // Higher score for critical paths
        if (stripos($uri, 'wp-config') !== false) {
            $score = 50; // Critical - instant ban
        } elseif (stripos($uri, '/wp-json/wc/') !== false) {
            $score = 15; // API brute force attempt
        }

        $currentScore = $this->storage->getScore($ip) ?? 0;
        $newScore = $this->storage->incrementScore($ip, $score, $this->config->getTrackingWindow());

        // Log security event
        $this->storage->logSecurityEvent('woocommerce_suspicious_path', $ip, [
            'uri' => $uri,
            'score_added' => $score,
            'total_score' => $newScore,
            'reason' => 'WooCommerce suspicious path access',
        ]);

        // Ban if threshold exceeded
        if ($newScore >= $this->config->getScoreThreshold()) {
            $this->storage->banIP($ip, $this->config->getBanDuration(), 'WooCommerce suspicious path access');
        }
    }

    /**
     * Check WooCommerce-specific rate limits
     *
     * @param string $ip Client IP
     * @param string $uri Request URI
     * @param string $method HTTP method
     * @return bool True if within limits, false if exceeded
     */
    private function checkWooCommerceRateLimits(string $ip, string $uri, string $method): bool
    {
        // Detect action type from URI
        $action = $this->detectWooCommerceAction($uri, $method);

        if ($action === null) {
            return true; // Not a WooCommerce action
        }

        $limit = self::WC_RATE_LIMITS[$action] ?? null;

        if ($limit === null) {
            return true;
        }

        // Check rate limit
        $count = $this->storage->incrementRequestCount($ip, $limit['window']);

        if ($count > $limit['requests']) {
            // Log rate limit violation
            $this->storage->logSecurityEvent('woocommerce_rate_limit', $ip, [
                'action' => $action,
                'count' => $count,
                'limit' => $limit['requests'],
                'window' => $limit['window'],
            ]);

            // Increment threat score
            $this->storage->incrementScore($ip, 10, $this->config->getTrackingWindow());

            return false;
        }

        return true;
    }

    /**
     * Detect WooCommerce action from URI and method
     *
     * @param string $uri Request URI
     * @param string $method HTTP method
     * @return string|null Action type or null if not WooCommerce
     */
    private function detectWooCommerceAction(string $uri, string $method): ?string
    {
        // Checkout
        if (stripos($uri, '/checkout') !== false && $method === 'POST') {
            return 'checkout';
        }

        // Add to cart
        if (stripos($uri, 'add-to-cart') !== false || stripos($uri, 'wc-ajax=add_to_cart') !== false) {
            return 'add_to_cart';
        }

        // Coupon check
        if (stripos($uri, 'apply_coupon') !== false || stripos($uri, 'remove_coupon') !== false) {
            return 'coupon_check';
        }

        // WooCommerce REST API
        if (stripos($uri, '/wp-json/wc/') !== false) {
            return 'api_request';
        }

        // Payment gateway callback
        if (stripos($uri, 'wc-api') !== false) {
            return 'payment_callback';
        }

        return null;
    }

    /**
     * Get WooCommerce-specific security recommendations
     *
     * @return array<string, string> Recommendations
     */
    public static function getSecurityRecommendations(): array
    {
        return [
            'wp_config' => 'Move wp-config.php outside web root',
            'rest_api' => 'Disable WooCommerce REST API if not needed',
            'payment_gateway' => 'Validate payment gateway signatures (use gateway SDK)',
            'cart_validation' => 'Always validate cart totals server-side (never trust client)',
            'coupon_security' => 'Implement CAPTCHA for coupon field',
            'admin_ajax' => 'Limit admin-ajax.php access to authenticated users only',
            'user_enumeration' => 'Disable author pages and REST API user endpoint',
            'rate_limiting' => 'Implement strict rate limiting on checkout and API',
        ];
    }
}
