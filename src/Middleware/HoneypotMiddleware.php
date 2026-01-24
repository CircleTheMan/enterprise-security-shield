<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Middleware;

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;
use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Exceptions\HoneypotAccessException;
use Senza1dio\SecurityShield\Utils\IPUtils;

/**
 * Honeypot Middleware - Framework-Agnostic Trap System
 *
 * MISSION:
 * Detect and instantly ban attackers accessing honeypot endpoints.
 * Gather intelligence to identify scanner type, origin, and techniques.
 * Send realistic fake responses to waste attacker's time and resources.
 *
 * FEATURES:
 * - 50+ default honeypot endpoints (/.env, /phpinfo.php, /wp-admin, etc.)
 * - Instant 7-day ban (configurable via SecurityConfig)
 * - Intelligence gathering (fingerprinting, scanner identification)
 * - Realistic fake responses (fake env files, API docs, SQL dumps)
 * - Framework-agnostic (works with any PHP application)
 * - PSR-3 compatible logging
 * - Zero configuration required (smart defaults)
 *
 * USAGE:
 * ```php
 * $config = new SecurityConfig();
 * $honeypot = new HoneypotMiddleware($config);
 *
 * // Early in request lifecycle (before routing)
 * if ($honeypot->isHoneypotPath($_SERVER['REQUEST_URI'])) {
 *     $honeypot->handle($_SERVER, $_GET, $_POST);
 *     exit; // Never reached - middleware exits after fake response
 * }
 * ```
 *
 * HONEYPOT ENDPOINTS:
 * - Config files: /.env, /config.php, /.git/config
 * - CMS: /wp-admin, /wp-login.php, /administrator
 * - Info disclosure: /phpinfo.php, /info.php
 * - Backups: /backup.sql, /db.sql, /dump.sql
 * - Cloud credentials: /.aws/credentials, /.ssh/id_rsa
 * - API: /api/v1/debug, /graphql, /swagger.json
 *
 * INTELLIGENCE GATHERED:
 * - IP address, User-Agent, HTTP headers (fingerprint)
 * - Scanner type identification (Nikto, SQLMap, etc.)
 * - Timestamp, request method, query string
 * - VPS/Cloud provider detection
 * - Threat level assessment
 *
 * FAKE RESPONSES:
 * - Realistic fake data to confuse bots
 * - Random delays (100-500ms) to slow down scanners
 * - Multiple fake DB types (MySQL, PostgreSQL, MongoDB)
 * - Fake credentials, API keys, AWS keys
 * - HTML, JSON, SQL, plain text responses
 *
 * PERFORMANCE:
 * - < 1ms overhead for legitimate users (fast path detection)
 * - Redis ban check in parallel with path detection
 * - Zero impact on legitimate traffic
 *
 * @package Senza1dio\SecurityShield\Middleware
 * @version 2.0.0
 * @author  senza1dio
 * @license MIT
 */
class HoneypotMiddleware
{
    /** @var SecurityConfig Configuration object */
    private SecurityConfig $config;

    /** @var array<string> Honeypot trap paths */
    private array $honeypotPaths;

    /** @var array<string, true> Honeypot exact paths (O(1) lookup) */
    private array $honeypotExactPaths = [];

    /** @var StorageInterface|null Storage backend */
    private ?StorageInterface $storage;

    /** @var LoggerInterface|null Logger instance */
    private ?LoggerInterface $logger;

    /** @var array<string, mixed> Collected intelligence data */
    private array $intelligence = [];

    /** @var array<string> Trusted proxy IPs/CIDRs for IP extraction */
    private array $trustedProxies = [];

    /**
     * Default honeypot paths (50+ traps)
     * These are common paths attackers scan for vulnerabilities
     */
    private const DEFAULT_HONEYPOT_PATHS = [
        // Environment & Config Files (CRITICAL)
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/.env.staging',
        '/.env.backup',
        '/config.php',
        '/configuration.php',
        '/settings.php',
        '/database.yml',
        '/database.php',
        '/db_config.php',

        // Version Control (HIGH PRIORITY)
        '/.git/',
        '/.git/config',
        '/.git/HEAD',
        '/.git/index',
        '/.svn/',
        '/.svn/entries',
        '/.hg/',
        '/.hg/hgrc',

        // PHP Info & Debug (HIGH PRIORITY)
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/debug.php',
        '/_phpinfo.php',
        '/php.php',

        // WordPress & CMS (COMMON SCANS)
        '/wp-admin',
        '/wp-admin/',
        '/wp-login.php',
        '/wp-config.php',
        '/wp-content/',
        '/wp-includes/',
        '/administrator',
        '/administrator/',
        '/admin.php',
        '/admin/',

        // Database Backups (HIGH VALUE)
        '/backup.sql',
        '/db.sql',
        '/dump.sql',
        '/database.sql',
        '/backup.zip',
        '/backup.tar.gz',
        '/db_backup.sql',

        // Cloud Credentials (CRITICAL)
        '/.aws/',
        '/.aws/credentials',
        '/.aws/config',
        '/aws/credentials',
        '/.ssh/',
        '/.ssh/id_rsa',
        '/.ssh/id_rsa.pub',
        '/.ssh/authorized_keys',

        // Shell & Backdoors (MALICIOUS)
        '/shell.php',
        '/c99.php',
        '/r57.php',
        '/webshell.php',
        '/backdoor.php',

        // API & Documentation (INTELLIGENCE)
        '/api/v1/debug',
        '/api/v2/debug',
        '/graphql',
        '/swagger.json',
        '/openapi.json',
        '/api-docs',

        // Other Common Scans
        '/.htpasswd',
        '/.htaccess.bak',
        '/robots.txt.bak',
        '/.DS_Store',
    ];

    /**
     * Constructor
     *
     * @param SecurityConfig $config Security configuration
     * @param array<int, string> $honeypotPaths Custom honeypot paths (empty = use defaults)
     */
    public function __construct(SecurityConfig $config, array $honeypotPaths = [])
    {
        $this->config = $config;
        $this->honeypotPaths = empty($honeypotPaths) ? self::DEFAULT_HONEYPOT_PATHS : $honeypotPaths;
        $this->storage = $config->getStorage();
        $this->logger = $config->getLogger();
        $this->trustedProxies = $config->getTrustedProxies();

        // Build O(1) hash maps for fast path matching
        // Separate maps for exact paths and directory prefixes
        foreach ($this->honeypotPaths as $path) {
            // Skip wildcards - they need regex matching
            if (str_contains($path, '*')) {
                continue;
            }

            // Normalize: remove trailing slash for exact match
            $normalized = rtrim($path, '/');
            $this->honeypotExactPaths[$normalized] = true;

            // Also add with trailing slash for directories
            if (str_ends_with($path, '/')) {
                $this->honeypotExactPaths[$path] = true;
            }
        }
    }

    /**
     * Check if path matches honeypot endpoint
     *
     * PERFORMANCE: O(n) linear search but n is small (~50 paths)
     * Could be optimized with hash table for 1000+ paths
     *
     * @param string $path Request path (from REQUEST_URI)
     * @return bool True if honeypot path detected
     */
    public function isHoneypotPath(string $path): bool
    {
        // Fast path: Check if honeypot is enabled
        if (!$this->config->isHoneypotEnabled()) {
            return false;
        }

        // Normalize path (remove query string, decode URL)
        $normalizedPath = $this->normalizePath($path);

        // FAST PATH: O(1) hash lookup for exact matches (~90% of honeypot paths)
        if (isset($this->honeypotExactPaths[$normalizedPath])) {
            return true;
        }

        // SLOW PATH: Check prefix matches and wildcards (only for directory traps)
        foreach ($this->honeypotPaths as $honeypotPath) {
            // Prefix match (for directory traps like /.git/)
            if (str_ends_with($honeypotPath, '/') && str_starts_with($normalizedPath, $honeypotPath)) {
                return true;
            }

            // Contains match (for wildcards)
            if (str_contains($honeypotPath, '*') && $this->wildcardMatch($honeypotPath, $normalizedPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set trusted proxies for IP extraction
     *
     * Must be called before handle() for correct IP resolution behind proxies.
     *
     * @param array<string> $proxies List of trusted proxy IPs/CIDRs
     * @return self
     */
    public function setTrustedProxies(array $proxies): self
    {
        $this->trustedProxies = $proxies;
        return $this;
    }

    /**
     * Handle honeypot access (ban + gather intelligence + fake response)
     *
     * THROWS HoneypotAccessException with fake response content.
     * Caller must catch and output the response.
     *
     * WHY EXCEPTION INSTEAD OF exit():
     * - Works with long-running processes (Swoole, RoadRunner, ReactPHP)
     * - Testable with PHPUnit (no exit during tests)
     * - Allows cleanup handlers to run (fastcgi_finish_request)
     *
     * USAGE:
     * ```php
     * try {
     *     $honeypot->handle($_SERVER);
     * } catch (HoneypotAccessException $e) {
     *     echo $e->getResponse();
     *     exit; // or return for long-running
     * }
     * ```
     *
     * @param array<string, mixed> $server $_SERVER superglobal
     * @param array<string, mixed> $get $_GET superglobal (default: [])
     * @param array<string, mixed> $post $_POST superglobal (default: [])
     * @return bool True if not a honeypot access (pass-through)
     * @throws HoneypotAccessException When honeypot path accessed
     */
    public function handle(array $server, array $get = [], array $post = []): bool
    {
        $requestURIRaw = $server['REQUEST_URI'] ?? '/';
        $requestURI = is_string($requestURIRaw) ? $requestURIRaw : '/';
        $requestPath = $this->normalizePath($requestURI);

        // FAST PATH: Check if this is a honeypot path
        if (!$this->isHoneypotPath($requestURI)) {
            // Not a honeypot - allow request to continue
            return true;
        }

        // HONEYPOT DETECTED - Process attack
        $clientIP = IPUtils::extractClientIP($server, $this->trustedProxies);

        $userAgentRaw = $server['HTTP_USER_AGENT'] ?? '';
        $userAgent = is_string($userAgentRaw) ? $userAgentRaw : '';

        $methodRaw = $server['REQUEST_METHOD'] ?? 'GET';
        $method = is_string($methodRaw) ? $methodRaw : 'GET';

        // Step 1: Gather intelligence BEFORE banning (forensics)
        $this->intelligence = $this->gatherIntelligence($server, $requestPath, $method);

        // Step 2: Instant ban via Storage backend
        $this->banAttacker($clientIP, $requestPath);

        // Step 3: Log security event
        $this->logHoneypotAccess($clientIP, $requestPath, $userAgent);

        // Step 4: Generate fake response and throw exception
        // Caller should catch HoneypotAccessException and send response
        $response = $this->generateFakeResponse($requestPath);

        throw new HoneypotAccessException($response, $clientIP, $requestPath);
    }

    /**
     * Get collected intelligence data
     *
     * Useful for testing and custom logging
     *
     * @return array<string, mixed> Intelligence data (empty if handle() not called yet)
     */
    public function getIntelligence(): array
    {
        return $this->intelligence;
    }

    /**
     * Generate fake response based on path type
     *
     * @param string $path Honeypot path
     * @return string Response content
     */
    public function generateFakeResponse(string $path): string
    {
        // Add random delay (100-500ms) to slow down scanners
        usleep(random_int(100000, 500000));

        // Determine response type based on path
        $pathLower = strtolower($path);

        if (str_contains($pathLower, '.env')) {
            return $this->generateFakeEnvFile();
        } elseif (str_contains($pathLower, 'phpinfo')) {
            return $this->generateFakePhpInfo();
        } elseif (str_contains($pathLower, 'wp-admin') || str_contains($pathLower, 'wp-login')) {
            return $this->generateFakeWordPressLogin();
        } elseif (str_contains($pathLower, '.git')) {
            return $this->generateFakeGitConfig();
        } elseif (str_contains($pathLower, 'graphql')) {
            return $this->generateFakeGraphQL();
        } elseif (str_contains($pathLower, 'swagger') || str_contains($pathLower, 'openapi')) {
            return $this->generateFakeSwagger();
        } elseif (str_contains($pathLower, 'api/')) {
            return $this->generateFakeAPI($path);
        } elseif (str_contains($pathLower, '.sql') || str_contains($pathLower, 'backup') || str_contains($pathLower, 'dump')) {
            return $this->generateFakeSQLDump();
        } elseif (str_contains($pathLower, 'config') || str_contains($pathLower, 'settings')) {
            return $this->generateFakeConfigFile();
        } elseif (str_contains($pathLower, 'debug') || str_contains($pathLower, 'log')) {
            return $this->generateFakeDebugLog();
        } elseif (str_contains($pathLower, '.aws') || str_contains($pathLower, '.ssh')) {
            return $this->generateFakeCloudCredentials($path);
        } else {
            return $this->generateGeneric404();
        }
    }

    /**
     * @deprecated Use handle() which throws HoneypotAccessException instead
     */
    public function sendFakeResponse(string $path): string
    {
        return $this->generateFakeResponse($path);
    }

    /**
     * Normalize request path for matching
     *
     * NOTE: We keep trailing slashes to properly match directory honeypots.
     * Both /wp-admin and /wp-admin/ should be detected.
     *
     * @param string $path Raw request path
     * @return string Normalized path (lowercase, no query string)
     */
    private function normalizePath(string $path): string
    {
        // Remove query string
        $parsedPath = parse_url($path, PHP_URL_PATH);
        $path = (is_string($parsedPath)) ? $parsedPath : $path;

        // URL decode (rawurldecode prevents + → space conversion for path security)
        // Apply multiple times to handle double-encoding attacks (%252e%252e%252f)
        // LIMIT: Max 5 iterations to prevent infinite loop with malformed input
        $maxIterations = 5;
        $i = 0;
        $decoded = rawurldecode($path);
        while ($decoded !== $path && $i++ < $maxIterations) {
            $path = $decoded;
            $decoded = rawurldecode($path);
        }

        // Resolve path traversal by collapsing segments
        // /foo/../.env → /.env, /a/b/../../.env → /.env
        $segments = explode('/', $path);
        $resolved = [];
        foreach ($segments as $segment) {
            if ($segment === '..') {
                // Go up one directory (pop if possible)
                if (!empty($resolved) && end($resolved) !== '') {
                    array_pop($resolved);
                }
            } elseif ($segment !== '.' && $segment !== '') {
                // Add valid segment (skip empty and single dot)
                $resolved[] = $segment;
            }
        }
        $path = '/' . implode('/', $resolved);

        // Collapse multiple slashes (//admin → /admin) to prevent bypass
        $path = (string) preg_replace('#/+#', '/', $path);

        // Normalize to lowercase for case-insensitive matching
        $path = strtolower($path);

        // DO NOT remove trailing slash - needed for directory matching
        // Both /wp-admin and /wp-admin/ should be detected

        return $path;
    }

    /**
     * Wildcard pattern matching (basic implementation)
     *
     * @param string $pattern Pattern with * wildcards
     * @param string $subject String to match
     * @return bool True if matches
     */
    private function wildcardMatch(string $pattern, string $subject): bool
    {
        // Cache compiled regex patterns to avoid recompilation on every request
        static $regexCache = [];

        if (!isset($regexCache[$pattern])) {
            $regexCache[$pattern] = '/^' . str_replace(['\*', '\?'], ['.*', '.'], preg_quote($pattern, '/')) . '$/i';
        }

        return preg_match($regexCache[$pattern], $subject) === 1;
    }

    /**
     * Gather intelligence about the attacker
     *
     * @param array<string, mixed> $server $_SERVER data
     * @param string $path Request path
     * @param string $method HTTP method
     * @return array<string, mixed> Intelligence data
     */
    private function gatherIntelligence(array $server, string $path, string $method): array
    {
        // Use resolved IP (handles proxies correctly)
        $ip = IPUtils::extractClientIP($server, $this->trustedProxies);

        $userAgentRaw = $server['HTTP_USER_AGENT'] ?? '';
        $userAgent = is_string($userAgentRaw) ? $userAgentRaw : '';

        return [
            'timestamp' => time(),
            'datetime' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'path' => $path,
            'method' => $method,
            'user_agent' => $userAgent,

            // HTTP Headers fingerprint
            'headers' => [
                'accept' => $server['HTTP_ACCEPT'] ?? '',
                'accept_language' => $server['HTTP_ACCEPT_LANGUAGE'] ?? '',
                'accept_encoding' => $server['HTTP_ACCEPT_ENCODING'] ?? '',
                'connection' => $server['HTTP_CONNECTION'] ?? '',
                'cache_control' => $server['HTTP_CACHE_CONTROL'] ?? '',
                'referer' => $server['HTTP_REFERER'] ?? '',
                'origin' => $server['HTTP_ORIGIN'] ?? '',
                'x_forwarded_for' => $server['HTTP_X_FORWARDED_FOR'] ?? '',
                'x_real_ip' => $server['HTTP_X_REAL_IP'] ?? '',
            ],

            // Request fingerprint
            'query_string' => $server['QUERY_STRING'] ?? '',
            'content_type' => $server['CONTENT_TYPE'] ?? '',
            'content_length' => $server['CONTENT_LENGTH'] ?? 0,

            // Scanner identification
            'scanner_type' => $this->identifyScannerType($userAgent, $path),
            'threat_level' => 'critical', // Honeypot access = always critical
        ];
    }

    /**
     * Identify scanner type from User-Agent and path patterns
     *
     * @param string $userAgent User-Agent header
     * @param string $path Request path
     * @return string Scanner type
     */
    private function identifyScannerType(string $userAgent, string $path): string
    {
        $uaLower = strtolower($userAgent);

        // Known scanners (vulnerability assessment tools)
        $scanners = [
            'sqlmap' => 'SQLMap (SQL Injection)',
            'nikto' => 'Nikto (Web Scanner)',
            'nmap' => 'Nmap (Port Scanner)',
            'burp' => 'Burp Suite (Pentest)',
            'acunetix' => 'Acunetix (Vuln Scanner)',
            'nessus' => 'Nessus (Vuln Scanner)',
            'wpscan' => 'WPScan (WordPress)',
            'dirbuster' => 'DirBuster (Dir Enum)',
            'gobuster' => 'Gobuster (Dir Enum)',
            'ffuf' => 'FFUF (Fuzzer)',
            'nuclei' => 'Nuclei (Vuln Scanner)',
            'metasploit' => 'Metasploit (Exploit Framework)',
            'zaproxy' => 'OWASP ZAP (Web Scanner)',
            'masscan' => 'Masscan (Port Scanner)',
            'curl' => 'cURL (Manual/Script)',
            'python-requests' => 'Python Requests',
            'go-http-client' => 'Go HTTP Client',
            'axios' => 'Axios (Node.js)',
            'wget' => 'wget (CLI Tool)',
        ];

        foreach ($scanners as $pattern => $name) {
            if (str_contains($uaLower, $pattern)) {
                return $name;
            }
        }

        // Path-based identification (case-insensitive for all paths)
        $pathLower = strtolower($path);
        if (str_contains($pathLower, 'wp-') || str_contains($pathLower, 'wordpress')) {
            return 'WordPress Scanner';
        }
        if (str_contains($pathLower, '.sql') || str_contains($pathLower, 'backup')) {
            return 'Database Dumper';
        }
        if (str_contains($pathLower, 'api/') || str_contains($pathLower, 'graphql')) {
            return 'API Enumerator';
        }
        if (str_contains($pathLower, '.env') || str_contains($pathLower, 'config')) {
            return 'Config Hunter';
        }
        if (str_contains($pathLower, '.git') || str_contains($pathLower, '.svn')) {
            return 'VCS Dumper';
        }
        if (str_contains($pathLower, '.aws') || str_contains($pathLower, '.ssh')) {
            return 'Cloud Credential Hunter';
        }

        return 'Unknown Scanner';
    }

    /**
     * Ban attacker via Storage backend
     *
     * @param string $ip Client IP
     * @param string $path Honeypot path
     * @return void
     */
    private function banAttacker(string $ip, string $path): void
    {
        if (!$this->storage) {
            return; // No storage configured - skip ban
        }

        try {
            $duration = $this->config->getHoneypotBanDuration();
            $reason = "Honeypot access: {$path}";

            $this->storage->banIP($ip, $duration, $reason);
        } catch (\Throwable $e) {
            // Don't fail if ban fails - log error but continue
            if ($this->logger) {
                $this->logger->error('Failed to ban honeypot attacker', [
                    'ip' => $ip,
                    'path' => $path,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Log honeypot access via Logger
     *
     * @param string $ip Client IP
     * @param string $path Honeypot path
     * @param string $userAgent User-Agent
     * @return void
     */
    private function logHoneypotAccess(string $ip, string $path, string $userAgent): void
    {
        if (!$this->logger) {
            return; // No logger configured
        }

        $this->logger->warning('HONEYPOT ACCESS DETECTED', [
            'ip' => $ip,
            'path' => $path,
            'user_agent' => $userAgent,
            'scanner_type' => $this->intelligence['scanner_type'] ?? 'unknown',
            'threat_level' => 'critical',
            'action' => 'banned',
            'ban_duration' => $this->config->getHoneypotBanDuration(),
            'intelligence' => $this->intelligence,
        ]);

        // Also log to storage events (if supported)
        if ($this->storage && $this->config->isIntelligenceEnabled()) {
            try {
                $this->storage->logSecurityEvent('honeypot', $ip, $this->intelligence);
            } catch (\Throwable $e) {
                // Ignore storage errors
            }
        }
    }

    // ========================================
    // FAKE RESPONSE GENERATORS
    // ========================================

    /**
     * Generate fake .env file with honeypot credentials
     *
     * @return string Fake env file content
     */
    private function generateFakeEnvFile(): string
    {
        // Set headers
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/plain');
        }

        // Randomize fake database types to waste bot time
        $fakeDbTypes = [
            [
                'connection' => 'mysql',
                'port' => 3306,
                'database' => 'prod_db_live',
                'username' => 'dbadmin',
                'password' => 'P@ssw0rd!Fake123',
            ],
            [
                'connection' => 'pgsql',
                'port' => 5432,
                'database' => 'postgres_production',
                'username' => 'postgres',
                'password' => 'Pg$Admin2024!Fake',
            ],
            [
                'connection' => 'mongodb',
                'port' => 27017,
                'database' => 'mongo_prod_db',
                'username' => 'mongo_admin',
                'password' => 'M0ng0DB!P@ss456',
            ],
        ];

        $selectedDb = $fakeDbTypes[array_rand($fakeDbTypes)];

        return <<<ENV
# Production Environment Configuration
APP_NAME=ProductionApp
APP_ENV=production
APP_KEY=base64:FAKE_KEY_aB3dEfGhIjKlMnOpQrStUvWxYz0123456789
APP_DEBUG=false
APP_URL=https://api.production.internal

# Database Configuration
DB_CONNECTION={$selectedDb['connection']}
DB_HOST=db-master.internal.cloud
DB_PORT={$selectedDb['port']}
DB_DATABASE={$selectedDb['database']}
DB_USERNAME={$selectedDb['username']}
DB_PASSWORD={$selectedDb['password']}

# Redis Configuration
REDIS_HOST=redis-cluster.internal.cloud
REDIS_PASSWORD=R3d1s!FakeP@ss789
REDIS_PORT=6379

# AWS Credentials (FAKE)
AWS_ACCESS_KEY_ID=AKIAFAKEACCESSKEY12345
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=production-backups-fake

# API Keys (FAKE)
STRIPE_SECRET=fake_stripe_key_51H4a8KBhX9zP2mQ7rYnW3fA0sLd6eUi
TWILIO_AUTH_TOKEN=FAKE_twilio_auth_token_useless
SENDGRID_API_KEY=SG.FakeKey123456789.AbCdEfGhIjKlMnOp

# Admin Credentials (FAKE)
ADMIN_EMAIL=admin@production-internal.fake
ADMIN_PASSWORD=Admin!P@ssw0rd123Fake

ENV;
    }

    /**
     * Generate fake PHP info page
     *
     * @return string Fake HTML page
     */
    private function generateFakePhpInfo(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/html; charset=utf-8');
        }

        return <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>phpinfo()</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        td { border: 1px solid #ccc; padding: 8px; }
        .e { background: #ccf; font-weight: bold; }
        .v { background: #fff; }
    </style>
</head>
<body>
<h1>PHP Version 7.4.33 (FAKE)</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux prod-web-01 5.15.0-generic</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.4.54 (Ubuntu)</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/7.4/apache2/php.ini</td></tr>
<tr><td class="e">register_globals</td><td class="v">On (INSECURE - FAKE)</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">On (INSECURE - FAKE)</td></tr>
<tr><td class="e">display_errors</td><td class="v">On (INSECURE - FAKE)</td></tr>
<tr><td class="e">mysqli.default_user</td><td class="v">root</td></tr>
<tr><td class="e">mysqli.default_pw</td><td class="v">FakeP@ssword123!</td></tr>
</table>
</body>
</html>
HTML;
    }

    /**
     * Generate fake WordPress login page
     *
     * @return string Fake HTML page
     */
    private function generateFakeWordPressLogin(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/html; charset=utf-8');
        }

        return <<<HTML
<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>Log In &lsaquo; Enterprise Site &#8212; WordPress</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto; background: #f1f1f1; }
        .login { max-width: 320px; margin: 100px auto; background: #fff; padding: 26px 24px; border: 1px solid #ddd; }
        .login h1 { text-align: center; }
        .login label { display: block; margin-bottom: 5px; }
        .login input { width: 100%; padding: 8px; margin-bottom: 16px; border: 1px solid #ccc; }
        .login .button { background: #2271b1; color: #fff; padding: 10px; border: none; cursor: pointer; width: 100%; }
    </style>
</head>
<body class="login">
    <div class="login">
        <h1>Powered by WordPress</h1>
        <form method="post" action="/wp-admin">
            <label for="user_login">Username or Email Address</label>
            <input type="text" name="log" id="user_login" required>

            <label for="user_pass">Password</label>
            <input type="password" name="pwd" id="user_pass" required>

            <button type="submit" class="button">Log In</button>
        </form>
    </div>
</body>
</html>
HTML;
    }

    /**
     * Generate fake .git/config file
     *
     * @return string Fake git config
     */
    private function generateFakeGitConfig(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/plain');
        }

        return <<<GIT
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/enterprise-org/production-app.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = Production Deploy Bot
	email = deploy-bot@enterprise-internal.fake
[credential]
	helper = store
GIT;
    }

    /**
     * Generate fake GraphQL introspection response
     *
     * @return string Fake JSON response
     */
    private function generateFakeGraphQL(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: application/json');
        }

        $response = [
            'data' => [
                '__schema' => [
                    'queryType' => ['name' => 'Query'],
                    'mutationType' => ['name' => 'Mutation'],
                    'types' => [
                        [
                            'name' => 'User',
                            'fields' => [
                                ['name' => 'id', 'type' => 'ID'],
                                ['name' => 'email', 'type' => 'String'],
                                ['name' => 'password_hash', 'type' => 'String'],
                                ['name' => 'api_token', 'type' => 'String'],
                                ['name' => 'credit_card', 'type' => 'String'],
                            ],
                        ],
                        [
                            'name' => 'AdminConfig',
                            'fields' => [
                                ['name' => 'secret_key', 'type' => 'String'],
                                ['name' => 'database_password', 'type' => 'String'],
                                ['name' => 'aws_access_key', 'type' => 'String'],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        return json_encode($response, JSON_PRETTY_PRINT) ?: '{}';
    }

    /**
     * Generate fake Swagger/OpenAPI documentation
     *
     * @return string Fake JSON response
     */
    private function generateFakeSwagger(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: application/json');
        }

        $response = [
            'openapi' => '3.0.0',
            'info' => [
                'title' => 'Internal API (CONFIDENTIAL)',
                'version' => '2.0.0',
                'description' => 'Internal production API - DO NOT EXPOSE',
            ],
            'servers' => [
                ['url' => 'https://api-internal.production.cloud/v2'],
            ],
            'paths' => [
                '/users' => [
                    'get' => [
                        'summary' => 'List all users with passwords',
                        'description' => 'INSECURE - Returns password hashes',
                        'security' => [['ApiKey' => []]],
                    ],
                ],
                '/admin/database' => [
                    'get' => [
                        'summary' => 'Get database credentials',
                        'description' => 'Returns live database connection string',
                    ],
                ],
                '/debug/sql' => [
                    'post' => [
                        'summary' => 'Execute raw SQL query',
                        'description' => 'Dev endpoint - TODO: Remove in production',
                    ],
                ],
            ],
            'components' => [
                'securitySchemes' => [
                    'ApiKey' => [
                        'type' => 'apiKey',
                        'in' => 'header',
                        'name' => 'X-API-KEY',
                    ],
                ],
            ],
        ];

        return json_encode($response, JSON_PRETTY_PRINT) ?: '{}';
    }

    /**
     * Generate fake API response
     *
     * @param string $path Request path
     * @return string Fake JSON response
     */
    private function generateFakeAPI(string $path): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: application/json');
        }

        // Different fake data based on path - looks realistic
        if (str_contains($path, 'users')) {
            $response = [
                'success' => true,
                'data' => [
                    ['id' => 1, 'email' => 'admin@company.com', 'role' => 'admin', 'password_hash' => '$2y$10$KV3JzZ8vL.Qn9YpX2wBqAeRhTm6sUyK1cDfGhJkLmNoPqRsTuVwX'],
                    ['id' => 2, 'email' => 'user@company.com', 'role' => 'user', 'api_token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
                ],
                'meta' => ['total' => 2, 'page' => 1],
            ];
        } elseif (str_contains($path, 'debug') || str_contains($path, 'internal')) {
            $response = [
                'debug' => true,
                'database' => [
                    'host' => 'db-master.internal.cloud',
                    'user' => 'app_user',
                    'pass' => 'Pr0d#SecretDB!2024',
                ],
                'redis' => [
                    'host' => 'redis-cluster.internal.cloud',
                    'password' => 'R3d1s#Cache!Key',
                ],
                'environment' => 'production',
            ];
        } else {
            $response = [
                'error' => 'Unauthorized',
                'message' => 'Valid API key required',
                'code' => 401,
            ];
        }

        return json_encode($response, JSON_PRETTY_PRINT) ?: '{}';
    }

    /**
     * Generate fake SQL dump
     *
     * @return string Fake SQL content
     */
    private function generateFakeSQLDump(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: application/sql');
            header('Content-Disposition: attachment; filename="backup_' . date('Y-m-d') . '.sql"');
        }

        return <<<SQL
-- MySQL dump 10.19  Distrib 8.0.32
-- Host: db-master.internal.cloud
-- Database: production_app

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS=0;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `api_key` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` VALUES
(1, 'admin@company.com', '\$2y\$10\$KV3JzZ8vL.Qn9YpX2wBqAeRhTm6sUyK1cDfGhJkLmNoPqRsTuVwX', 'sk_api_7f8a9b2c3d4e5f6g'),
(2, 'dev@company.com', '\$2y\$10\$Xm4NpL7kQ9rS2tUvWxYz0A1bC3dE5fG6hI8jK0lM2nO4pQ6rS8t', 'sk_api_1a2b3c4d5e6f7g8h');

--
-- Table structure for table `api_credentials`
--

CREATE TABLE `api_credentials` (
  `service` varchar(50),
  `api_key` varchar(128),
  `secret` varchar(256)
);

INSERT INTO `api_credentials` VALUES
('stripe', 'fake_stripe_51H4a8KBhX9zP2mQ7rYnW3fA0', 'whsec_1a2b3c4d5e6f7g8h9i0j'),
('aws', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

SET FOREIGN_KEY_CHECKS=1;
SQL;
    }

    /**
     * Generate fake config file
     *
     * @return string Fake PHP config
     */
    private function generateFakeConfigFile(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/plain');
        }

        return <<<CONFIG
<?php
/**
 * Production Configuration
 * Last updated: 2024-01-15
 */

define('DB_HOST', 'db-master.internal.cloud');
define('DB_USER', 'app_production');
define('DB_PASS', 'Pr0d#SecretDB!2024@Secure');
define('DB_NAME', 'production_app');

define('REDIS_HOST', 'redis-cluster.internal.cloud');
define('REDIS_PASS', 'R3d1s#C4che!Pr0d_Key');

define('ADMIN_USER', 'sysadmin');
define('ADMIN_PASS', 'Adm1n!Str0ng#Pass2024');

define('API_SECRET', 'fake_api_key_9f8e7d6c5b4a3210fedcba98');
define('JWT_SECRET', 'jwt_s3cr3t_k3y_pr0duct10n_2024');

// AWS Credentials
define('AWS_KEY', 'AKIAIOSFODNN7EXAMPLE');
define('AWS_SECRET', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

// Stripe
define('STRIPE_SECRET', 'fake_stripe_key_51H4a8KBhX9zP2mQ7rYnW3fA0sLd6eUi');
CONFIG;
    }

    /**
     * Generate fake debug/error log
     *
     * @return string Fake log content
     */
    private function generateFakeDebugLog(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/plain');
        }

        $now = date('Y-m-d H:i:s');
        $yesterday = date('Y-m-d H:i:s', strtotime('-1 day'));
        $hourAgo = date('Y-m-d H:i:s', strtotime('-1 hour'));

        return <<<LOG
[{$yesterday}] INFO: Application started - PID 12847
[{$yesterday}] DEBUG: Database connected to db-master.internal.cloud:5432
[{$yesterday}] DEBUG: Redis connection established (cluster mode)
[{$yesterday}] INFO: Background jobs started (5 workers)
[{$hourAgo}] DEBUG: SQL Query: SELECT * FROM users WHERE last_login > NOW() - INTERVAL '24 hours'
[{$hourAgo}] DEBUG: Found 3,482 active users
[{$hourAgo}] INFO: Cache warmup completed (hit ratio: 94.7%)
[{$now}] DEBUG: AWS S3 sync: production-backups bucket
[{$now}] DEBUG: S3 Access Key: AKIAIOSFODNN7EXAMPLE
[{$now}] DEBUG: Stripe webhook received: invoice.paid
[{$now}] INFO: Payment processed: $149.99 (customer: cus_L2b3K4m5N6o7P8q)
[{$now}] DEBUG: Email sent to admin@company.com: Daily report
[{$now}] INFO: Health check passed - all services operational
LOG;
    }

    /**
     * Generate fake cloud credentials (AWS, SSH keys)
     *
     * @param string $path Request path
     * @return string Fake credentials
     */
    private function generateFakeCloudCredentials(string $path): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(200);
            header('Content-Type: text/plain');
        }

        if (str_contains($path, '.aws')) {
            return <<<AWS
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = eu-west-1
output = json
AWS;
        }

        if (str_contains($path, '.ssh') || str_contains($path, 'id_rsa')) {
            return <<<SSH
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFKpHlIvR2p2Y2RBHxMGEL1ypGpXiTrH5YHk8m6WZvOQAAAJhJ8K3WSfCt
1gAAAAtzc2gtZWQyNTUxOQAAACBFKpHlIvR2p2Y2RBHxMGEL1ypGpXiTrH5YHk8m6WZvOQ
AAAEDmfR6qKMxpL1u3K4R4HyWRf2YKqwCbD9JFMW6vLRhg8UUqkeUi9HanZjZEEfEwYQvX
KkaleMsflgeTybpZm84AAAAFZGVwbG95AQIDBAUGBwgJCg==
-----END OPENSSH PRIVATE KEY-----
SSH;
        }

        return "Access Denied";
    }

    /**
     * Generate generic 404 response
     *
     * @return string 404 response
     */
    private function generateGeneric404(): string
    {
        if (PHP_SAPI !== 'cli') {
            http_response_code(404);
            header('Content-Type: text/plain');
        }

        return "404 Not Found";
    }
}
