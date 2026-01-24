<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Middleware;

use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;
use Senza1dio\SecurityShield\Services\BotVerifier;
use Senza1dio\SecurityShield\Services\ThreatPatterns;
use Senza1dio\SecurityShield\Utils\IPUtils;

/**
 * Security Middleware - Threat Detection and IP Management
 *
 * Framework-agnostic security middleware that provides threat detection,
 * scanning detection and automatic IP banning. Designed to protect web
 * applications from vulnerability scanners, bot attacks, and malicious traffic.
 *
 * FEATURES:
 * - IP whitelist/blacklist (instant pass/block)
 * - Threat score accumulation system (50+ patterns)
 * - Legitimate bot verification (DNS + IP range)
 * - Geographic blocking (configurable countries)
 * - Fake User-Agent detection (obsolete browsers)
 * - Honeypot detection support
 * - Auto-ban on threshold exceeded (configurable)
 * - Dual-write storage (cache + persistent)
 *
 * SCORING SYSTEM:
 * - +30 points: Critical path scanning (/.env, /.git, /phpinfo.php)
 * - +15 points: CMS path scanning (/wp-admin, /wp-content)
 * - +10 points: Config file scanning (/config.php, /database.yml)
 * - +30 points: Known scanner User-Agents (sqlmap, nikto, etc.)
 * - +50 points: Fake/obsolete User-Agents (IE 9/10, ancient browsers)
 * - +100 points: Empty/NULL User-Agent (instant ban)
 * - +20 points: Rate limit exceeded
 * - THRESHOLD: 50 points triggers auto-ban (configurable)
 *
 * PERFORMANCE:
 * - <1ms for whitelisted IPs (instant pass)
 * - <1ms for banned IPs (cache hit)
 * - <5ms for normal requests (no DNS lookup)
 * - <100ms for bot verification (DNS lookup, cached)
 * - Zero overhead for legitimate users
 *
 * USAGE:
 * ```php
 * $config = new SecurityConfig();
 * $config->setStorage($storage)
 *        ->setLogger($logger)
 *        ->addIPWhitelist(['127.0.0.1', '192.168.1.0/24']);
 *
 * $middleware = new SecurityMiddleware($config);
 *
 * // In middleware pipeline
 * if (!$middleware->handle($_SERVER, $_GET, $_POST)) {
 *     http_response_code(403);
 *     echo 'Access Denied';
 *     exit;
 * }
 * ```
 *
 * FRAMEWORK-AGNOSTIC DESIGN:
 * - Zero dependencies on Laravel, Symfony, or any framework
 * - Works with $_SERVER, $_GET, $_POST arrays
 * - Returns bool (true = allowed, false = blocked)
 * - Storage via interface (Redis, DB, Memory)
 * - Logger via interface (PSR-3 compatible)
 *
 * @package Senza1dio\SecurityShield\Middleware
 * @version 2.0.0
 * @author Senza1dio Security Team
 * @license MIT
 */
class SecurityMiddleware
{
    /**
     * Security configuration
     */
    protected SecurityConfig $config;

    /**
     * Storage backend for IP scores, bans, and caching
     */
    protected StorageInterface $storage;

    /**
     * Logger for security events
     */
    protected LoggerInterface $logger;

    /**
     * Bot verifier instance (DNS + IP verification)
     */
    private ?BotVerifier $botVerifier = null;

    /**
     * GeoIP service instance
     */
    private ?\Senza1dio\SecurityShield\Services\GeoIP\GeoIPService $geoip = null;

    /**
     * Metrics collector instance
     */
    private ?\Senza1dio\SecurityShield\Contracts\MetricsCollectorInterface $metrics = null;

    /**
     * Webhook notifier instance
     */
    private ?\Senza1dio\SecurityShield\Services\WebhookNotifier $webhooks = null;

    /**
     * Block reason (set when request is blocked)
     */
    private ?string $blockReason = null;

    /**
     * Current threat score
     */
    private int $threatScore = 0;

    /**
     * Resolved client IP (proxy-aware)
     *
     * Set once during handle() and reused by child classes.
     * Ensures consistent IP across all security checks.
     */
    protected ?string $clientIp = null;

    /**
     * Constructor
     *
     * @param SecurityConfig $config Security configuration with storage and logger
     * @throws \InvalidArgumentException If storage or logger not set in config
     */
    public function __construct(SecurityConfig $config)
    {
        $this->config = $config;

        // CRITICAL: Storage and Logger are REQUIRED for WAF to function
        $storage = $config->getStorage();
        $logger = $config->getLogger();

        if ($storage === null) {
            throw new \InvalidArgumentException(
                'SecurityConfig must have storage configured. Use $config->setStorage($storage)'
            );
        }

        if ($logger === null) {
            throw new \InvalidArgumentException(
                'SecurityConfig must have logger configured. Use $config->setLogger($logger)'
            );
        }

        // Now we know they're non-null, assign to properties
        $this->storage = $storage;
        $this->logger = $logger;

        // Initialize bot verifier if enabled
        if ($config->isBotVerificationEnabled()) {
            $this->botVerifier = new BotVerifier($this->storage, $this->logger);
        }
    }

    /**
     * Set GeoIP service (optional but recommended)
     *
     * @param \Senza1dio\SecurityShield\Services\GeoIP\GeoIPService $geoip
     * @return self
     */
    public function setGeoIP(\Senza1dio\SecurityShield\Services\GeoIP\GeoIPService $geoip): self
    {
        $this->geoip = $geoip;
        return $this;
    }

    /**
     * Set metrics collector (optional)
     *
     * @param \Senza1dio\SecurityShield\Contracts\MetricsCollectorInterface $metrics
     * @return self
     */
    public function setMetrics(\Senza1dio\SecurityShield\Contracts\MetricsCollectorInterface $metrics): self
    {
        $this->metrics = $metrics;
        return $this;
    }

    /**
     * Set webhook notifier (optional)
     *
     * @param \Senza1dio\SecurityShield\Services\WebhookNotifier $webhooks
     * @return self
     */
    public function setWebhooks(\Senza1dio\SecurityShield\Services\WebhookNotifier $webhooks): self
    {
        $this->webhooks = $webhooks;
        return $this;
    }

    /**
     * Handle WAF security checks
     *
     * WORKFLOW:
     * 0. EARLY BAN CHECK - Block banned IPs immediately (cache-only, no storage writes)
     * 1. Extract IP, path, User-Agent from request
     * 2. Check IP whitelist (instant pass)
     * 3. Check IP blacklist (instant block)
     * 4. Check if IP is already banned (regular check with DB fallback)
     * 5. Check if legitimate bot (DNS/IP verification)
     * 6. Detect threat patterns (paths, User-Agents, geo)
     * 7. Update threat score
     * 8. Auto-ban if threshold exceeded
     * 9. Return true (allowed) or false (blocked)
     *
     * @param array<string, mixed> $server $_SERVER superglobal (REMOTE_ADDR, REQUEST_URI, HTTP_USER_AGENT)
     * @param array<string, mixed> $get $_GET superglobal (optional, for query string analysis)
     * @param array<string, mixed> $post $_POST superglobal (optional, for POST analysis)
     * @return bool True if request allowed, false if blocked
     */
    public function handle(array $server, array $get = [], array $post = []): bool
    {
        // Reset state
        $this->blockReason = null;
        $this->threatScore = 0;

        // ====================================================================
        // STEP 0: EARLY BAN CHECK (before ANY other operations)
        // ====================================================================
        //
        // CRITICAL OPTIMIZATION: Check ban status BEFORE extracting IP from proxy headers,
        // parsing URLs, or ANY other operations. This prevents banned IPs from:
        // - Incrementing rate limit counters (DoS storage amplification)
        // - Running SQL/XSS pattern matching (CPU waste)
        // - Triggering scoring calculations (storage writes)
        //
        // PERFORMANCE: Uses cache-only check (no DB query) for <1ms response.
        // If cache miss, IP will be allowed this request but banned on next request.
        //
        // NOTE: This check uses REMOTE_ADDR directly (no proxy header parsing yet)
        // to maximize performance. Proxy header parsing happens in STEP 1.
        // ====================================================================

        $remoteAddrRaw = $server['REMOTE_ADDR'] ?? 'unknown';
        $remoteAddr = is_string($remoteAddrRaw) ? $remoteAddrRaw : 'unknown';

        // STEP 0: Early ban check using REMOTE_ADDR (performance optimization)
        //
        // WHY REMOTE_ADDR and not real IP here?
        // - REMOTE_ADDR is already available, no header parsing needed
        // - For non-proxied requests, REMOTE_ADDR = real IP (common case)
        // - For proxied requests, we re-check with real IP in STEP 1
        //
        // FAIL-SAFE: If REMOTE_ADDR is proxy IP and client is banned,
        // ban check is repeated after IP extraction (lines ~277-289).
        //
        // TRADE-OFF: Micro-inefficiency (1 extra Redis call) vs. complexity.
        // This is intentional "fail-open on fast path" design.
        if (filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
            try {
                if ($this->storage->isIpBannedCached($remoteAddr)) {
                    $this->blockReason = 'ip_banned_early';
                    return false; // BLOCKED
                }
            } catch (\Throwable $e) {
                // FAIL-CLOSED: If configured, block on storage failure
                if ($this->config->isFailClosedEnabled()) {
                    $this->blockReason = 'storage_failure_failclosed';
                    return false; // BLOCK ALL on storage failure
                }
                // FAIL-OPEN: Continue (default behavior)
            }
        }

        // ====================================================================
        // STEP 1: Extract request data (with proxy support)
        // ====================================================================

        // Extract real client IP (handles proxy/load balancer headers)
        // Store in protected property for child class access
        $this->clientIp = $this->extractRealClientIP($server, $this->config->getTrustedProxies());
        $ip = $this->clientIp; // Local alias for readability

        // If IP differs from REMOTE_ADDR, check ban status again
        if ($ip !== $remoteAddr && filter_var($ip, FILTER_VALIDATE_IP)) {
            try {
                if ($this->storage->isIpBannedCached($ip)) {
                    $this->blockReason = 'ip_banned_early';
                    return false; // BLOCKED
                }
            } catch (\Throwable $e) {
                // FAIL-CLOSED policy
                if ($this->config->isFailClosedEnabled()) {
                    $this->blockReason = 'storage_failure_failclosed';
                    return false;
                }
            }
        }

        $requestUri = $server['REQUEST_URI'] ?? '/';
        $requestUriString = is_string($requestUri) ? $requestUri : '/';

        // Handle malformed URLs gracefully
        $pathRaw = parse_url($requestUriString, PHP_URL_PATH);
        $path = (is_string($pathRaw) && $pathRaw !== '') ? $pathRaw : '/';

        $userAgentRaw = $server['HTTP_USER_AGENT'] ?? '';
        // Trim to catch " " (space-only) User-Agent bypass attempts
        $userAgent = is_string($userAgentRaw) ? trim($userAgentRaw) : '';

        // Invalid IP - block
        if ($ip === 'unknown' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->blockReason = 'invalid_ip';
            $this->logger->warning('WAF: Invalid IP address', [
                'ip' => $ip,
                'path' => $path,
                'remote_addr' => $server['REMOTE_ADDR'] ?? 'unknown',
            ]);
            return false;
        }

        // ====================================================================
        // STEP 2: Check IP whitelist FIRST (instant pass - before ALL checks)
        // ====================================================================

        if ($this->isIPWhitelisted($ip)) {
            $this->logger->info('WAF: Whitelisted IP bypassed all security checks', [
                'ip' => $ip,
                'path' => $path,
                'whitelist_type' => 'config',
            ]);
            return true; // ALLOWED
        }

        // ====================================================================
        // STEP 3: Check IP blacklist (instant block)
        // ====================================================================

        if ($this->isIPBlacklisted($ip)) {
            $this->blockReason = 'blacklisted';
            $this->logger->error('WAF: Blacklisted IP blocked', [
                'ip' => $ip,
                'path' => $path,
            ]);
            $this->recordMetric('blocked', 'blacklist');
            return false; // BLOCKED
        }

        // ====================================================================
        // STEP 3.5: GeoIP Country Blocking (NEW FEATURE 2026-01-23)
        // ====================================================================

        if ($this->geoip && $this->config->isGeoIPEnabled()) {
            $blockedCountries = $this->config->getBlockedCountries();

            if (!empty($blockedCountries)) {
                $country = $this->geoip->getCountry($ip);

                if ($country && in_array($country, $blockedCountries)) {
                    $this->blockReason = "geo_blocked_{$country}";
                    $this->logger->warning('WAF: Country blocked', [
                        'ip' => $ip,
                        'country' => $country,
                        'path' => $path,
                    ]);

                    // Ban IP for configured duration (default: 30 days)
                    $this->storage->banIP($ip, $this->config->getGeoIPBanDuration(), "Country blocked: {$country}");
                    $this->recordMetric('blocked', 'geo_country');
                    $this->sendWebhook('country_blocked', [
                        'ip' => $ip,
                        'country' => $country,
                        'path' => $path,
                    ]);

                    return false; // BLOCKED
                }
            }
        }

        // ====================================================================
        // STEP 4: Check if IP is already banned (BEFORE incrementing counters!)
        // ====================================================================

        try {
            if ($this->storage->isBanned($ip)) {
                $this->blockReason = 'ip_banned';
                $this->logger->debug('WAF: Banned IP attempted access', [
                    'ip' => $ip,
                    'path' => $path,
                ]);
                // CRITICAL: Do NOT increment request count for banned IPs
                // (prevents DoS storage amplification attack)
                return false; // BLOCKED
            }
        } catch (\Throwable $e) {
            // FAIL-CLOSED policy on storage failure
            if ($this->config->isFailClosedEnabled()) {
                $this->blockReason = 'storage_failure_failclosed';
                $this->logger->error('WAF: Storage failure - fail-closed active', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
                return false; // BLOCK on storage failure
            }
            // FAIL-OPEN: Continue (storage unavailable, assume not banned)
        }

        // ====================================================================
        // STEP 5: Check if legitimate bot (skip security checks if verified)
        // ====================================================================

        if ($this->config->isBotVerificationEnabled() && $this->botVerifier !== null) {
            if ($this->botVerifier->verifyBot($ip, $userAgent)) {
                // Legitimate bot verified - allow without scoring
                $this->logger->info('WAF: Legitimate bot verified', [
                    'ip' => $ip,
                    'user_agent' => $userAgent,
                    'path' => $path,
                ]);
                // CRITICAL: Do NOT increment request count for legitimate bots
                return true; // ALLOWED
            }
        }

        // ====================================================================
        // STEP 5.5: Rate Limiting Check (MOVED HERE - after ban/bot checks)
        // ====================================================================

        // Increment request count ONLY for non-banned, non-bot IPs
        // (prevents DoS storage amplification attack)
        $rateLimitWindow = $this->config->getRateLimitWindow();
        $rateLimitMax = $this->config->getRateLimitMax();
        $requestCount = $this->storage->incrementRequestCount($ip, $rateLimitWindow);

        // ====================================================================
        // STEP 6: Detect threat patterns and calculate score
        // ====================================================================

        $score = 0;
        $reasons = [];

        // Check critical vulnerability paths
        if (ThreatPatterns::isCriticalPath($path)) {
            $score += ThreatPatterns::getCriticalPathScore();
            $reasons[] = 'critical_path';
        }

        // Check CMS scanning paths
        if (ThreatPatterns::isCMSPath($path)) {
            $score += ThreatPatterns::getCMSPathScore();
            $reasons[] = 'cms_scan';
        }

        // Check config file paths
        if (ThreatPatterns::isConfigPath($path)) {
            $score += ThreatPatterns::getConfigPathScore();
            $reasons[] = 'config_scan';
        }

        // Check User-Agent patterns
        if (empty($userAgent)) {
            // NULL/empty User-Agent = instant ban
            $score += ThreatPatterns::getNullUserAgentScore();
            $reasons[] = 'null_user_agent';
        } elseif (ThreatPatterns::isScannerUserAgent($userAgent)) {
            // Known scanner User-Agent
            $score += ThreatPatterns::getScannerUserAgentScore();
            $reasons[] = 'scanner_user_agent';
        } elseif (ThreatPatterns::isFakeUserAgent($userAgent)) {
            // Fake/obsolete User-Agent (IE9, ancient Chrome)
            $score += ThreatPatterns::getFakeUserAgentScore();
            $reasons[] = 'fake_user_agent';
        }

        // Check geographic blocking (requires country code from external service)
        // NOTE: Country code detection left to implementation (use GeoIP service)
        // Example: $countryCode = $this->getCountryCode($ip);

        // ====================================================================
        // STEP 6.5: Rate Limit Scoring (requestCount already incremented above)
        // ====================================================================

        if ($requestCount > $rateLimitMax) {
            $score += ThreatPatterns::getRateLimitScore();
            $reasons[] = 'rate_limit_exceeded';

            $this->logger->warning('WAF: Rate limit exceeded', [
                'ip' => $ip,
                'path' => $path,
                'requests' => $requestCount,
                'limit' => $rateLimitMax,
                'window' => $rateLimitWindow,
            ]);
        }

        // ====================================================================
        // STEP 7: Update threat score if suspicious activity detected
        // ====================================================================

        if ($score > 0) {
            $this->threatScore = $score;

            // Increment IP score in storage
            $totalScore = $this->storage->incrementScore(
                $ip,
                $score,
                $this->config->getTrackingWindow()
            );

            $this->logger->warning('WAF: Suspicious activity detected', [
                'ip' => $ip,
                'path' => $path,
                'user_agent' => $userAgent,
                'score_added' => $score,
                'total_score' => $totalScore,
                'reasons' => $reasons,
                'threshold' => $this->config->getScoreThreshold(),
                'distance_to_ban' => $this->config->getScoreThreshold() - $totalScore,
            ]);

            // ================================================================
            // STEP 8: Auto-ban if threshold exceeded
            // ================================================================

            if ($totalScore >= $this->config->getScoreThreshold()) {
                $this->blockReason = 'threshold_exceeded';

                // Ban IP
                $this->storage->banIP(
                    $ip,
                    $this->config->getBanDuration(),
                    implode(', ', $reasons)
                );

                // Log critical security event
                $this->logger->critical('WAF: IP automatically banned for vulnerability scanning', [
                    'ip' => $ip,
                    'total_score' => $totalScore,
                    'reasons' => $reasons,
                    'ban_duration' => $this->config->getBanDuration(),
                    'threshold' => $this->config->getScoreThreshold(),
                    'path' => $path,
                    'user_agent' => $userAgent,
                ]);

                // Log security event to storage
                $this->storage->logSecurityEvent('auto_ban', $ip, [
                    'total_score' => $totalScore,
                    'reasons' => $reasons,
                    'path' => $path,
                    'user_agent' => $userAgent,
                    'ban_duration' => $this->config->getBanDuration(),
                    'timestamp' => time(),
                ]);

                return false; // BLOCKED
            }
        }

        // ====================================================================
        // STEP 9: Request allowed
        // ====================================================================

        return true; // ALLOWED
    }

    /**
     * Get block reason (if request was blocked)
     *
     * USAGE:
     * ```php
     * if (!$waf->handle($_SERVER)) {
     *     $reason = $waf->getBlockReason();
     *     // 'blacklisted', 'ip_banned', 'threshold_exceeded', etc.
     * }
     * ```
     *
     * @return string|null Block reason or null if not blocked
     */
    public function getBlockReason(): ?string
    {
        return $this->blockReason;
    }

    /**
     * Get threat score added in current request
     *
     * Returns the score added ONLY in the current request, NOT the total accumulated score.
     * For total score, query storage->getScore($ip).
     *
     * RENAMED from getThreatScore() for clarity (was misleading name).
     *
     * @return int Threat score added this request (0 = safe, 50+ may trigger ban)
     */
    public function getLastRequestScore(): int
    {
        return $this->threatScore;
    }

    /**
     * Get threat score added in current request (DEPRECATED - use getLastRequestScore)
     *
     * @deprecated Use getLastRequestScore() instead for clarity
     * @return int Threat score added this request
     */
    public function getThreatScore(): int
    {
        return $this->getLastRequestScore();
    }

    /**
     * Check if IP is whitelisted
     *
     * Whitelisted IPs bypass ALL security checks (ban, scoring, patterns).
     * Supports both single IPs and CIDR ranges.
     *
     * @param string $ip Client IP address
     * @return bool True if whitelisted
     */
    protected function isIPWhitelisted(string $ip): bool
    {
        $whitelist = $this->config->getIPWhitelist();

        if (empty($whitelist)) {
            return false;
        }

        return IPUtils::isInAnyCIDR($ip, $whitelist);
    }

    /**
     * Check if IP is blacklisted
     *
     * Blacklisted IPs are instantly blocked (no scoring, no verification).
     * Supports both single IPs and CIDR ranges.
     *
     * @param string $ip Client IP address
     * @return bool True if blacklisted
     */
    protected function isIPBlacklisted(string $ip): bool
    {
        $blacklist = $this->config->getIPBlacklist();

        if (empty($blacklist)) {
            return false;
        }

        return IPUtils::isInAnyCIDR($ip, $blacklist);
    }

    /**
     * Get configuration instance
     *
     * @return SecurityConfig
     */
    public function getConfig(): SecurityConfig
    {
        return $this->config;
    }

    /**
     * Get bot verifier instance
     *
     * @return BotVerifier|null
     */
    public function getBotVerifier(): ?BotVerifier
    {
        return $this->botVerifier;
    }

    /**
     * Extract real client IP from proxy headers
     *
     * Delegates to IPUtils::extractClientIP() for centralized IP extraction logic.
     *
     * SECURITY: Only trusts proxy headers if REMOTE_ADDR matches trusted proxy list.
     * This prevents IP spoofing attacks.
     *
     * Supported Headers (in priority order):
     * 1. CF-Connecting-IP (Cloudflare)
     * 2. X-Real-IP (Nginx)
     * 3. X-Forwarded-For (Standard proxy, takes first IP)
     * 4. REMOTE_ADDR (Direct connection)
     *
     * @param array<string, mixed> $server $_SERVER superglobal
     * @param array<string> $trustedProxies List of trusted proxy IPs/CIDRs
     * @return string Client IP address
     */
    protected function extractRealClientIP(array $server, array $trustedProxies = []): string
    {
        return IPUtils::extractClientIP($server, $trustedProxies);
    }

    /**
     * Record metric (if metrics collector configured)
     *
     * @param string $action Action (e.g., 'blocked', 'allowed', 'banned')
     * @param string $reason Reason (e.g., 'blacklist', 'geo_country', 'sql_injection')
     * @return void
     */
    private function recordMetric(string $action, string $reason): void
    {
        if ($this->metrics) {
            $this->metrics->increment("waf_{$action}_total");
            $this->metrics->increment("waf_{$action}_{$reason}");
        }
    }

    /**
     * Send webhook notification (if webhooks configured)
     *
     * @param string $event Event type
     * @param array<string, mixed> $data Event data
     * @return void
     */
    private function sendWebhook(string $event, array $data): void
    {
        if ($this->webhooks) {
            $this->webhooks->notify($event, $data);
        }
    }

    /**
     * Get statistics (requires metrics collector)
     *
     * @return array<string, float> Statistics
     */
    public function getStatistics(): array
    {
        if ($this->metrics) {
            return $this->metrics->getAll();
        }

        return [];
    }

    /**
     * Sanitize params for logging (prevents log poisoning + storage bloat)
     *
     * Security: Limits each param to 500 chars, handles non-scalar values
     * Prevents: Log injection, emoji flood, binary data, UTF-16 attacks
     *
     * @internal Available for subclasses to use in custom logging
     * @param array<string, mixed> $params Raw GET/POST params
     * @return array<string, string> Sanitized params safe for logging
     */
    protected function sanitizeParamsForLogging(array $params): array
    {
        return array_map(
            fn($v) => is_scalar($v) ? mb_substr((string)$v, 0, 500) : '[non-scalar]',
            $params
        );
    }

    /**
     * Get resolved client IP (proxy-aware)
     *
     * Returns the real client IP extracted during handle().
     * Child classes MUST use this instead of re-extracting IP.
     *
     * CRITICAL: Ensures consistent IP across all security checks:
     * - Early ban check
     * - Score accumulation
     * - Rate limiting
     * - Ban enforcement
     *
     * @return string Resolved client IP (or 'unknown' if not yet resolved)
     */
    protected function getClientIp(): string
    {
        return $this->clientIp ?? 'unknown';
    }
}
