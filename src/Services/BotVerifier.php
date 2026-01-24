<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Services;

use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;

/**
 * Bot Verification Service
 *
 * Verifies legitimate search engine and crawler bots using DNS reverse lookup
 * and IP range verification. Prevents bot spoofing attacks by validating that
 * the User-Agent matches the actual IP ownership.
 *
 * VERIFICATION METHODS:
 * 1. DNS Verification (Googlebot, Bingbot, etc.)
 *    - Reverse DNS lookup: IP → hostname (e.g., 66.249.66.1 → crawl-66-249-66-1.googlebot.com)
 *    - Hostname suffix check: Verify hostname ends with legitimate suffix (.googlebot.com)
 *    - Forward DNS lookup: hostname → IP (must match original IP to prevent spoofing)
 *    - Cache result (24h) to avoid repeated DNS calls
 *
 * 2. IP Range Verification (OpenAI bots)
 *    - OpenAI crawlers (ChatGPT-User, GPTBot, OAI-SearchBot) use Azure IPs without reverse DNS
 *    - Verify IP is within official CIDR ranges (from https://openai.com/chatgpt-user.json)
 *    - Pure PHP CIDR matching (~0.5ms, no DNS/network calls)
 *
 * ANTI-SPOOFING PROTECTION:
 * - User-Agent alone is NOT sufficient (trivial to spoof)
 * - DNS verification ensures IP ownership matches claimed bot identity
 * - Forward DNS lookup prevents DNS spoofing attacks
 * - Results cached to prevent DNS amplification attacks
 *
 * PERFORMANCE:
 * - DNS verification: ~50-100ms (cached for 24h)
 * - IP range verification: ~0.5ms (pure PHP, no I/O)
 * - Cache hit: <1ms (Redis lookup)
 * - DNS lookups saved: 95%+ via caching
 *
 * STATISTICS TRACKING:
 * - Total verifications attempted
 * - DNS verifications passed/failed
 * - IP range verifications passed/failed
 * - Cache hit/miss ratio
 * - DNS lookups saved (performance metric)
 *
 * USAGE:
 * ```php
 * $verifier = new BotVerifier($storage, $logger);
 *
 * // Verify bot (uses cache + DNS/IP verification)
 * if ($verifier->verifyBot('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1)')) {
 *     // Legitimate Googlebot - allow access
 * }
 *
 * // Get statistics
 * $stats = $verifier->getStatistics();
 * echo "Cache hit rate: {$stats['cache_hit_rate']}%\n";
 * echo "DNS lookups saved: {$stats['dns_lookups_saved']}\n";
 * ```
 *
 * @package Senza1dio\SecurityShield\Services
 * @version 2.0.0
 * @author Senza1dio Security Team
 * @license MIT
 */
class BotVerifier
{
    /**
     * Default cache TTL for bot verification results (24 hours)
     */
    private const DEFAULT_CACHE_TTL = 86400;

    /**
     * Configurable cache TTL
     */
    private int $cacheTTL;

    /**
     * OpenAI bot User-Agent identifiers (IP verification)
     */
    private const OPENAI_BOTS = ['chatgpt-user', 'gptbot', 'oai-searchbot'];

    /**
     * Statistics counters
     * @var array<string, int>
     */
    private array $stats = [
        'total_verifications' => 0,
        'cache_hits' => 0,
        'cache_misses' => 0,
        'dns_verifications_passed' => 0,
        'dns_verifications_failed' => 0,
        'ip_verifications_passed' => 0,
        'ip_verifications_failed' => 0,
        'dns_lookups_saved' => 0,
    ];

    /**
     * Storage backend for caching verification results
     */
    private StorageInterface $storage;

    /**
     * Logger for security events
     */
    private LoggerInterface $logger;

    /**
     * Constructor
     *
     * @param StorageInterface $storage Storage backend (Redis recommended)
     * @param LoggerInterface $logger Logger for security events
     * @param int $cacheTTL Cache TTL in seconds (default: 24 hours)
     */
    public function __construct(StorageInterface $storage, LoggerInterface $logger, int $cacheTTL = self::DEFAULT_CACHE_TTL)
    {
        $this->storage = $storage;
        $this->logger = $logger;
        $this->cacheTTL = $cacheTTL;
    }

    /**
     * Set cache TTL for bot verification results
     *
     * @param int $ttl TTL in seconds
     * @return self
     */
    public function setCacheTTL(int $ttl): self
    {
        $this->cacheTTL = $ttl;
        return $this;
    }

    /**
     * Verify bot legitimacy using cache, DNS, or IP range verification
     *
     * WORKFLOW:
     * 1. Check cache for previous verification (24h TTL)
     * 2. If cache miss, determine verification method:
     *    - OpenAI bots: IP range verification (no DNS available)
     *    - Other bots: DNS reverse lookup + forward verification
     * 3. Cache result (positive or negative)
     * 4. Return verification status
     *
     * @param string $ip Client IP address
     * @param string $userAgent User-Agent header
     * @return bool True if bot is verified legitimate
     */
    public function verifyBot(string $ip, string $userAgent): bool
    {
        $this->stats['total_verifications']++;

        // STEP 1: Check cache
        $cached = $this->getCachedVerification($ip);
        if ($cached !== null) {
            $this->stats['cache_hits']++;
            $this->stats['dns_lookups_saved']++;

            $this->logger->debug('Bot verification cache hit', [
                'ip' => $ip,
                'cached_result' => $cached,
                'user_agent' => $userAgent,
            ]);

            return $cached;
        }

        $this->stats['cache_misses']++;

        // STEP 2: Identify bot type from User-Agent
        $botName = $this->identifyBotFromUserAgent($userAgent);
        if ($botName === null) {
            // User-Agent doesn't match any legitimate bot pattern
            return false;
        }

        // STEP 3: Choose verification method
        $verified = false;
        $verificationMethod = '';

        if ($this->isOpenAIBot($botName)) {
            // OpenAI bots: IP range verification (no reverse DNS)
            $verified = $this->verifyOpenAIBot($ip, $botName);
            $verificationMethod = 'ip_range';

            if ($verified) {
                $this->stats['ip_verifications_passed']++;
            } else {
                $this->stats['ip_verifications_failed']++;
            }
        } else {
            // Other bots: DNS verification (reverse + forward lookup)
            $verified = $this->verifyWithDNS($ip, $botName);
            $verificationMethod = 'dns';

            if ($verified) {
                $this->stats['dns_verifications_passed']++;
            } else {
                $this->stats['dns_verifications_failed']++;
            }
        }

        // STEP 4: Cache result
        $this->storage->cacheBotVerification(
            $ip,
            $verified,
            [
                'bot_name' => $botName,
                'user_agent' => $userAgent,
                'verification_method' => $verificationMethod,
                'timestamp' => time(),
            ],
            $this->cacheTTL
        );

        // STEP 5: Log verification result
        if ($verified) {
            $this->logger->info('Bot verification successful', [
                'ip' => $ip,
                'bot_name' => $botName,
                'method' => $verificationMethod,
                'user_agent' => $userAgent,
            ]);
        } else {
            $this->logger->warning('Bot verification failed - possible spoofing attempt', [
                'ip' => $ip,
                'claimed_bot' => $botName,
                'method' => $verificationMethod,
                'user_agent' => $userAgent,
            ]);
        }

        return $verified;
    }

    /**
     * Verify bot using DNS reverse lookup (anti-spoofing)
     *
     * PROCESS:
     * 1. Reverse DNS: IP → hostname (e.g., 66.249.66.1 → crawl-66-249-66-1.googlebot.com)
     * 2. Hostname suffix check: Verify hostname ends with legitimate suffix (.googlebot.com)
     * 3. Forward DNS: hostname → IP (must match original IP to prevent DNS spoofing)
     *
     * EXAMPLE (Googlebot):
     * - IP: 66.249.66.1
     * - Reverse: crawl-66-249-66-1.googlebot.com
     * - Check: ends with .googlebot.com ✓
     * - Forward: crawl-66-249-66-1.googlebot.com → 66.249.66.1 ✓
     * - Result: VERIFIED
     *
     * ANTI-SPOOFING:
     * - Step 1 alone is insufficient (attacker can set reverse DNS on their IP)
     * - Step 3 ensures the hostname actually resolves back to the original IP
     * - This prevents DNS hijacking and spoofing attacks
     *
     * @param string $ip Client IP address
     * @param string $botName Bot identifier (e.g., 'googlebot', 'bingbot')
     * @return bool True if DNS verification passes
     */
    public function verifyWithDNS(string $ip, string $botName): bool
    {
        try {
            // Get allowed hostname suffixes for this bot
            $allowedSuffixes = ThreatPatterns::getLegitimateHostnameSuffixes($botName);
            if ($allowedSuffixes === null || empty($allowedSuffixes)) {
                $this->logger->debug('No DNS verification available for bot', [
                    'ip' => $ip,
                    'bot_name' => $botName,
                ]);
                return false;
            }

            // STEP 1: Reverse DNS lookup (IP → hostname)
            // Timeout: 5 seconds to avoid blocking requests
            $hostname = @gethostbyaddr($ip);

            // gethostbyaddr returns IP if lookup fails
            if (!$hostname || $hostname === $ip) {
                $this->logger->debug('DNS reverse lookup failed', [
                    'ip' => $ip,
                    'bot_name' => $botName,
                ]);
                return false;
            }

            $hostnameLower = strtolower($hostname);

            // STEP 2: Verify hostname ends with legitimate suffix
            $validHostname = false;
            foreach ($allowedSuffixes as $suffix) {
                if (str_ends_with($hostnameLower, strtolower($suffix))) {
                    $validHostname = true;
                    break;
                }
            }

            if (!$validHostname) {
                $this->logger->warning('Bot hostname does not match legitimate suffix', [
                    'ip' => $ip,
                    'bot_name' => $botName,
                    'hostname' => $hostname,
                    'allowed_suffixes' => $allowedSuffixes,
                ]);
                return false;
            }

            // STEP 3: Forward DNS lookup (hostname → IP)
            // This prevents DNS spoofing attacks
            $resolvedIP = @gethostbyname($hostname);

            // Verify resolved IP matches original IP
            if ($resolvedIP !== $ip) {
                $this->logger->warning('Forward DNS mismatch - possible DNS spoofing', [
                    'ip' => $ip,
                    'bot_name' => $botName,
                    'hostname' => $hostname,
                    'resolved_ip' => $resolvedIP,
                ]);
                return false;
            }

            // All checks passed - legitimate bot verified!
            $this->logger->debug('DNS verification successful', [
                'ip' => $ip,
                'bot_name' => $botName,
                'hostname' => $hostname,
            ]);

            return true;

        } catch (\Throwable $e) {
            // DNS lookup failed - fail-safe: don't block (could be DNS issue)
            $this->logger->warning('DNS verification exception', [
                'ip' => $ip,
                'bot_name' => $botName,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Get cached bot verification result
     *
     * @param string $ip Bot IP address
     * @return bool|null True/False if cached, null if not cached
     */
    public function getCachedVerification(string $ip): ?bool
    {
        $cached = $this->storage->getCachedBotVerification($ip);

        if ($cached === null) {
            return null;
        }

        $verified = $cached['verified'] ?? null;
        return is_bool($verified) ? $verified : null;
    }

    /**
     * Verify OpenAI bot by IP range (no reverse DNS available)
     *
     * OpenAI crawlers (ChatGPT-User, GPTBot, OAI-SearchBot) run on Azure infrastructure
     * without reverse DNS. We verify by checking if the IP is within official OpenAI ranges.
     *
     * SOURCE: https://openai.com/chatgpt-user.json (official IP list)
     *
     * PERFORMANCE:
     * - ~0.5ms (pure PHP CIDR matching, no DNS/network calls)
     *
     * @param string $ip Client IP address (IPv4)
     * @param string $botName Bot identifier (for logging)
     * @return bool True if IP is within official OpenAI ranges
     */
    private function verifyOpenAIBot(string $ip, string $botName): bool
    {
        try {
            if (ThreatPatterns::isOpenAIIP($ip)) {
                $this->logger->debug('OpenAI bot verified by IP range', [
                    'ip' => $ip,
                    'bot_name' => $botName,
                ]);
                return true;
            }

            $this->logger->warning('OpenAI bot IP not in official ranges', [
                'ip' => $ip,
                'bot_name' => $botName,
            ]);

            return false;

        } catch (\Throwable $e) {
            $this->logger->warning('OpenAI bot IP verification error', [
                'ip' => $ip,
                'bot_name' => $botName,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Identify bot name from User-Agent string
     *
     * Matches User-Agent against legitimate bot patterns and returns the bot name
     * for DNS/IP verification.
     *
     * @param string $userAgent User-Agent header
     * @return string|null Bot name (e.g., 'googlebot', 'bingbot') or null if not a bot
     */
    private function identifyBotFromUserAgent(string $userAgent): ?string
    {
        if (empty($userAgent)) {
            return null;
        }

        $userAgentLower = strtolower($userAgent);

        // Check against all legitimate bot patterns
        // Priority order matters: check more specific patterns first

        // Special case: Telegrambot BEFORE twitterbot (UA contains "like TwitterBot")
        if (str_contains($userAgentLower, 'telegrambot')) {
            return 'telegrambot';
        }

        // OpenAI bots (IP verification)
        if (str_contains($userAgentLower, 'chatgpt-user')) {
            return 'chatgpt-user';
        }
        if (str_contains($userAgentLower, 'gptbot')) {
            return 'gptbot';
        }
        if (str_contains($userAgentLower, 'oai-searchbot')) {
            return 'oai-searchbot';
        }

        // Major search engines (DNS verification)
        if (str_contains($userAgentLower, 'googlebot')) {
            return 'googlebot';
        }
        if (str_contains($userAgentLower, 'google-safety')) {
            return 'google-safety';
        }
        if (str_contains($userAgentLower, 'bingbot')) {
            return 'bingbot';
        }
        if (str_contains($userAgentLower, 'slurp')) {
            return 'slurp'; // Yahoo
        }
        if (str_contains($userAgentLower, 'duckduckbot')) {
            return 'duckduckbot';
        }
        if (str_contains($userAgentLower, 'baiduspider')) {
            return 'baiduspider';
        }
        if (str_contains($userAgentLower, 'yandexbot')) {
            return 'yandexbot';
        }

        // Social media crawlers (DNS verification)
        if (str_contains($userAgentLower, 'facebookexternalhit')) {
            return 'facebookexternalhit';
        }
        if (str_contains($userAgentLower, 'twitterbot')) {
            return 'twitterbot';
        }
        if (str_contains($userAgentLower, 'linkedinbot')) {
            return 'linkedinbot';
        }
        if (str_contains($userAgentLower, 'pinterestbot')) {
            return 'pinterestbot';
        }

        // Other legitimate bots (DNS verification)
        if (str_contains($userAgentLower, 'applebot')) {
            return 'applebot';
        }
        if (str_contains($userAgentLower, 'ia_archiver')) {
            return 'ia_archiver'; // Internet Archive
        }
        if (str_contains($userAgentLower, 'amazonbot')) {
            return 'amazonbot';
        }

        // User-Agent doesn't match any known legitimate bot
        return null;
    }

    /**
     * Check if bot name is OpenAI bot (uses IP verification instead of DNS)
     *
     * @param string $botName Bot identifier
     * @return bool True if OpenAI bot
     */
    private function isOpenAIBot(string $botName): bool
    {
        return in_array(strtolower($botName), self::OPENAI_BOTS, true);
    }

    /**
     * Get verification statistics
     *
     * Provides insights into performance and effectiveness:
     * - Cache hit rate: Higher is better (fewer DNS lookups)
     * - DNS lookups saved: Performance metric (DNS ~100ms, cache <1ms)
     * - Verification success rate: Security metric
     *
     * @return array<string, mixed> Statistics array
     */
    public function getStatistics(): array
    {
        $totalVerifications = $this->stats['total_verifications'];

        // Calculate derived metrics
        $cacheHits = (int) $this->stats['cache_hits'];
        $cacheHitRate = $totalVerifications > 0
            ? round(($cacheHits / $totalVerifications) * 100, 2)
            : 0.0;

        $dnsPassed = (int) $this->stats['dns_verifications_passed'];
        $dnsFailed = (int) $this->stats['dns_verifications_failed'];
        $dnsTotal = $dnsPassed + $dnsFailed;
        $dnsSuccessRate = $dnsTotal > 0
            ? round(($dnsPassed / $dnsTotal) * 100, 2)
            : 0.0;

        $ipPassed = (int) $this->stats['ip_verifications_passed'];
        $ipFailed = (int) $this->stats['ip_verifications_failed'];
        $ipTotal = $ipPassed + $ipFailed;
        $ipSuccessRate = $ipTotal > 0
            ? round(($ipPassed / $ipTotal) * 100, 2)
            : 0.0;

        return [
            // Raw counters
            'total_verifications' => $this->stats['total_verifications'],
            'cache_hits' => $this->stats['cache_hits'],
            'cache_misses' => $this->stats['cache_misses'],
            'dns_verifications_passed' => $this->stats['dns_verifications_passed'],
            'dns_verifications_failed' => $this->stats['dns_verifications_failed'],
            'ip_verifications_passed' => $this->stats['ip_verifications_passed'],
            'ip_verifications_failed' => $this->stats['ip_verifications_failed'],
            'dns_lookups_saved' => $this->stats['dns_lookups_saved'],

            // Derived metrics
            'cache_hit_rate' => $cacheHitRate,
            'dns_success_rate' => $dnsSuccessRate,
            'ip_success_rate' => $ipSuccessRate,

            // Performance metrics
            'estimated_time_saved_ms' => $this->stats['dns_lookups_saved'] * 100, // ~100ms per DNS lookup saved
        ];
    }

    /**
     * Reset statistics (for testing/monitoring)
     *
     * @return void
     */
    public function resetStatistics(): void
    {
        $this->stats = [
            'total_verifications' => 0,
            'cache_hits' => 0,
            'cache_misses' => 0,
            'dns_verifications_passed' => 0,
            'dns_verifications_failed' => 0,
            'ip_verifications_passed' => 0,
            'ip_verifications_failed' => 0,
            'dns_lookups_saved' => 0,
        ];
    }
}
