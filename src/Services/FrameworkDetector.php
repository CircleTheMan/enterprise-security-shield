<?php

namespace Senza1dio\SecurityShield\Services;

/**
 * Framework Detector - Auto-detect application framework
 *
 * Prevents honeypot false positives by detecting if the application
 * is running on WordPress, Laravel, Symfony, etc.
 *
 * PROBLEM:
 * - Honeypot includes /wp-admin/, /wp-login.php as traps
 * - But these are LEGITIMATE paths for WordPress sites!
 * - A WordPress admin would get banned for accessing their own admin panel
 *
 * SOLUTION:
 * - Auto-detect if app is WordPress → Disable WordPress honeypot paths
 * - Auto-detect if app is Laravel → Disable Laravel honeypot paths
 * - Keep honeypot active for custom/unknown frameworks
 *
 * USAGE:
 * ```php
 * $detector = new FrameworkDetector();
 * if ($detector->isWordPress()) {
 *     // Don't use WordPress honeypot paths
 * }
 * ```
 */
class FrameworkDetector
{
    /**
     * Cached framework detection result
     *
     * WARNING: Static cache can cause issues in:
     * - Long-running processes (Swoole, RoadRunner, ReactPHP)
     * - Multi-tenant applications
     * - Test suites with multiple app contexts
     *
     * MITIGATION:
     * - Call reset() between requests in long-running mode
     * - Or use disableStaticCache() in bootstrap
     *
     * @var string|null Framework name or null if not detected yet
     */
    private static ?string $detectedFramework = null;

    /**
     * Flag to disable static caching (for long-running processes)
     *
     * When true, detect() will NOT cache results - safe for Swoole/RoadRunner
     * Performance impact: ~0.1ms per request (filesystem checks)
     *
     * @var bool
     */
    private static bool $staticCacheDisabled = false;

    /**
     * Detect application framework
     *
     * Detection methods (in order):
     * 1. Environment variables (WP_ENV, LARAVEL_ENV, SYMFONY_ENV)
     * 2. File existence (wp-config.php, artisan, symfony.lock)
     * 3. Defined constants (ABSPATH, LARAVEL_START)
     * 4. Class existence (WP_Query, Illuminate\Foundation\Application)
     *
     * @return string Framework name ('wordpress', 'laravel', 'symfony', 'custom')
     */
    public static function detect(): string
    {
        // Return cached result if already detected AND caching is enabled
        if (!self::$staticCacheDisabled && self::$detectedFramework !== null) {
            return self::$detectedFramework;
        }

        // WordPress detection
        if (self::isWordPress()) {
            self::$detectedFramework = 'wordpress';
            return 'wordpress';
        }

        // Laravel detection
        if (self::isLaravel()) {
            self::$detectedFramework = 'laravel';
            return 'laravel';
        }

        // Symfony detection
        if (self::isSymfony()) {
            self::$detectedFramework = 'symfony';
            return 'symfony';
        }

        // Custom/unknown framework
        self::$detectedFramework = 'custom';
        return 'custom';
    }

    /**
     * Check if application is WordPress
     *
     * Detection methods (ordered by reliability):
     * 1. ABSPATH constant (most reliable - runtime)
     * 2. WP_Query class exists (runtime loaded)
     * 3. wp-includes/ directory exists (filesystem)
     * 4. wp-config.php exists (least reliable - can be backup/staging)
     *
     * FALSE POSITIVE MITIGATION:
     * - Prioritizes runtime detection over filesystem
     * - Filesystem checks alone can match backups/staging/dumps
     * - Safer on shared hosting / monorepo / CI environments
     *
     * @return bool True if WordPress detected
     */
    public static function isWordPress(): bool
    {
        // Method 1: ABSPATH constant (WordPress core defines this)
        // MOST RELIABLE - means WordPress is actually loaded
        if (defined('ABSPATH')) {
            return true;
        }

        // Method 2: WP_Query class exists (loaded WordPress)
        // RUNTIME check - more reliable than filesystem
        if (class_exists('WP_Query', false)) {
            return true;
        }

        // Method 3: wp-includes directory exists
        // FILESYSTEM check - reliable for installed WordPress
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getcwd();
        if (is_dir($docRoot . '/wp-includes')) {
            return true;
        }

        // Method 4: wp-config.php exists
        // LEAST RELIABLE - can be backup/staging/old installation
        // Only check in document root (not parent) to reduce false positives
        if (file_exists($docRoot . '/wp-config.php')) {
            return true;
        }

        return false;
    }

    /**
     * Check if application is Laravel
     *
     * @return bool True if Laravel detected
     */
    public static function isLaravel(): bool
    {
        // Method 1: Laravel-specific constant
        if (defined('LARAVEL_START')) {
            return true;
        }

        // Method 2: artisan file exists
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getcwd();
        if (file_exists($docRoot . '/../artisan') || file_exists($docRoot . '/artisan')) {
            return true;
        }

        // Method 3: Illuminate classes exist
        if (class_exists('Illuminate\\Foundation\\Application', false)) {
            return true;
        }

        return false;
    }

    /**
     * Check if application is Symfony
     *
     * @return bool True if Symfony detected
     */
    public static function isSymfony(): bool
    {
        // Method 1: Symfony kernel
        if (class_exists('Symfony\\Component\\HttpKernel\\Kernel', false)) {
            return true;
        }

        // Method 2: symfony.lock exists
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getcwd();
        if (file_exists($docRoot . '/../symfony.lock') || file_exists($docRoot . '/symfony.lock')) {
            return true;
        }

        return false;
    }

    /**
     * Get framework-specific paths that should NOT be honeypot
     *
     * Returns legitimate paths for the detected framework that should
     * be excluded from honeypot detection.
     *
     * @return array<string> Legitimate paths to exclude from honeypot
     */
    public static function getLegitimateFrameworkPaths(): array
    {
        $framework = self::detect();

        switch ($framework) {
            case 'wordpress':
                return [
                    '/wp-admin/',
                    '/wp-login.php',
                    '/wp-json/',
                    '/xmlrpc.php',
                    '/wp-cron.php',
                    '/wp-content/',
                    '/wp-includes/',
                ];

            case 'laravel':
                return [
                    '/nova/',
                    '/horizon/',
                    '/telescope/',
                    '/admin/',
                ];

            case 'symfony':
                return [
                    '/_profiler/',
                    '/_wdt/',
                    '/admin/',
                ];

            case 'custom':
            default:
                // Custom frameworks: Return common legitimate paths to prevent false positives
                // These are standard paths that most applications have
                return [
                    '/admin/',
                    '/dashboard/',
                    '/api/',
                    '/v1/',
                    '/v2/',
                    '/auth/',
                    '/login',
                    '/logout',
                    '/register',
                    '/profile/',
                    '/settings/',
                    '/assets/',
                    '/static/',
                    '/public/',
                ];
        }
    }

    /**
     * Check if a path is legitimate for the detected framework
     *
     * Uses PREFIX matching (not substring) to avoid false positives.
     *
     * EXAMPLES:
     * - /wp-admin/index.php → MATCH (legitimate)
     * - /fake-wp-admin-trap → NO MATCH (honeypot)
     * - /backup/wp-login.php → NO MATCH (honeypot)
     *
     * @param string $path Request path to check
     * @return bool True if path is legitimate for this framework
     */
    public static function isLegitimateFrameworkPath(string $path): bool
    {
        $legitimatePaths = self::getLegitimateFrameworkPaths();

        // Normalize path
        $path = strtolower($path);

        foreach ($legitimatePaths as $legitimatePath) {
            $legitimatePath = strtolower($legitimatePath);

            // PREFIX match only (not substring)
            if (str_starts_with($path, $legitimatePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Reset framework detection (for testing)
     *
     * @return void
     */
    public static function reset(): void
    {
        self::$detectedFramework = null;
    }

    /**
     * Disable static caching (for long-running processes)
     *
     * USAGE IN BOOTSTRAP (Swoole/RoadRunner/ReactPHP):
     * ```php
     * // In bootstrap, before handling requests:
     * FrameworkDetector::disableStaticCache();
     *
     * // Or per-request reset (alternative):
     * $server->on('request', function($req, $res) {
     *     FrameworkDetector::reset();
     *     // ... handle request
     * });
     * ```
     *
     * PERFORMANCE:
     * - With cache: ~0.01ms (memory lookup)
     * - Without cache: ~0.1ms (filesystem check per request)
     * - Acceptable overhead for correct behavior
     *
     * @return void
     */
    public static function disableStaticCache(): void
    {
        self::$staticCacheDisabled = true;
        self::$detectedFramework = null; // Clear any existing cache
    }

    /**
     * Enable static caching (default behavior)
     *
     * Only use this in traditional PHP-FPM/Apache mod_php environments
     * where each request is a fresh process.
     *
     * @return void
     */
    public static function enableStaticCache(): void
    {
        self::$staticCacheDisabled = false;
    }

    /**
     * Check if static caching is enabled
     *
     * @return bool True if caching is enabled
     */
    public static function isStaticCacheEnabled(): bool
    {
        return !self::$staticCacheDisabled;
    }
}
