<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Config;

use Senza1dio\SecurityShield\Contracts\StorageInterface;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;

/**
 * Security Configuration - Fluent Builder API
 *
 * Framework-agnostic configuration for the Security Shield.
 *
 * ZERO-CONFIG DEFAULTS:
 * - Score threshold: 50 points (auto-ban)
 * - Ban duration: 24 hours
 * - Tracking window: 1 hour
 * - Honeypot: enabled
 * - Bot verification: enabled with DNS
 *
 * USAGE:
 * ```php
 * $config = (new SecurityConfig())
 *     ->setScoreThreshold(50)
 *     ->setBanDuration(86400)
 *     ->setRateLimitMax(100)
 *     ->setRateLimitWindow(60)
 *     ->setStorage($redisStorage)
 *     ->setLogger($logger);
 * ```
 *
 * @package Senza1dio\SecurityShield\Config
 */
class SecurityConfig
{
    /**
     * Factory method to create a new SecurityConfig instance
     *
     * Fluent API alternative to constructor for chaining:
     * ```php
     * $config = SecurityConfig::create()
     *     ->setScoreThreshold(50)
     *     ->setBanDuration(86400);
     * ```
     *
     * @return self
     */
    public static function create(): self
    {
        return new self();
    }

    /** @var int Threat score threshold for auto-ban (default: 50) */
    private int $scoreThreshold = 50;

    /** @var int Ban duration in seconds (default: 24h) */
    private int $banDuration = 86400;

    /** @var int Tracking window in seconds (default: 1h) */
    private int $trackingWindow = 3600;

    /** @var int Honeypot ban duration in seconds (default: 7 days) */
    private int $honeypotBanDuration = 604800;

    /** @var bool Enable honeypot trap endpoints */
    private bool $honeypotEnabled = true;

    /** @var bool Enable bot verification with DNS */
    private bool $botVerificationEnabled = true;

    /** @var int Bot verification cache TTL in seconds (default: 7 days) */
    private int $botCacheTTL = 604800;

    /** @var StorageInterface|null Storage backend (Redis, Database, Memory) */
    private ?StorageInterface $storage = null;

    /** @var LoggerInterface|null Logger instance (Monolog, Laravel, Symfony) */
    private ?LoggerInterface $logger = null;

    /** @var array<int, array{pattern: string, score: int, description: string}> Custom threat patterns to detect */
    private array $customPatterns = [];

    /** @var array<int, string> IP whitelist (never ban these IPs) */
    private array $ipWhitelist = [];

    /** @var array<int, string> IP blacklist (always ban these IPs) */
    private array $ipBlacklist = [];

    /** @var bool Enable intelligence gathering for honeypot */
    private bool $intelligenceEnabled = true;

    /** @var bool Send alerts on critical events */
    private bool $alertsEnabled = false;

    /** @var string|null Alert webhook URL */
    private ?string $alertWebhook = null;

    /** @var string Environment (production, staging, development) */
    private string $environment = 'production';

    /**
     * Max requests allowed per rate limit window
     *
     * NAMING: "rateLimitMax" (not "perMinute") to avoid confusion
     * when window != 60 seconds
     *
     * @var int Max requests per window (default: 100)
     */
    private int $rateLimitMax = 100;

    /** @var int Rate limit window in seconds (default: 60) */
    private int $rateLimitWindow = 60;

    /** @var array<int, string> Trusted proxy IPs/CIDRs (for X-Forwarded-For header trust) */
    private array $trustedProxies = [];

    /** @var array<int, string> Blocked country codes (ISO 3166-1 alpha-2) */
    private array $blockedCountries = [];

    /** @var bool Enable GeoIP detection */
    private bool $geoipEnabled = false;

    /** @var int GeoIP cache TTL in seconds (default: 24h) */
    private int $geoipCacheTTL = 86400;

    /** @var int GeoIP ban duration in seconds (default: 30 days) */
    private int $geoipBanDuration = 2592000;

    /**
     * Fail-closed mode: Ban users on storage failure (default: false = fail-open)
     *
     * FAIL-OPEN (false, default):
     * - Storage down → Allow traffic (high availability)
     * - PRO: Site stays online during Redis/DB outage
     * - CON: Attackers bypass bans during outage
     * - USE CASE: E-commerce, public sites
     *
     * FAIL-CLOSED (true):
     * - Storage down → Block traffic (high security)
     * - PRO: Security maintained during outage
     * - CON: Legitimate users blocked
     * - USE CASE: Banking, government, high-security
     *
     * @var bool Enable fail-closed mode (block on storage failure)
     */
    private bool $failClosed = false;

    /**
     * Set threat score threshold for auto-ban
     *
     * @param int $threshold Score threshold (1-1000)
     * @return self
     */
    public function setScoreThreshold(int $threshold): self
    {
        if ($threshold < 1 || $threshold > 1000) {
            throw new \InvalidArgumentException('Score threshold must be between 1 and 1000');
        }
        $this->scoreThreshold = $threshold;
        return $this;
    }

    /**
     * Set ban duration in seconds
     *
     * @param int $seconds Ban duration (60-2592000, max 30 days)
     * @return self
     */
    public function setBanDuration(int $seconds): self
    {
        if ($seconds < 60 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Ban duration must be between 60s and 30 days');
        }
        $this->banDuration = $seconds;
        return $this;
    }

    /**
     * Set tracking window in seconds
     *
     * @param int $seconds Tracking window (60-86400, max 24h)
     * @return self
     */
    public function setTrackingWindow(int $seconds): self
    {
        if ($seconds < 60 || $seconds > 86400) {
            throw new \InvalidArgumentException('Tracking window must be between 60s and 24h');
        }
        $this->trackingWindow = $seconds;
        return $this;
    }

    /**
     * Set honeypot ban duration in seconds
     *
     * @param int $seconds Ban duration (3600-2592000, max 30 days)
     * @return self
     */
    public function setHoneypotBanDuration(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Honeypot ban must be between 1h and 30 days');
        }
        $this->honeypotBanDuration = $seconds;
        return $this;
    }

    /**
     * Enable or disable honeypot trap endpoints
     *
     * @param bool $enabled
     * @return self
     */
    public function enableHoneypot(bool $enabled): self
    {
        $this->honeypotEnabled = $enabled;
        return $this;
    }

    /**
     * Enable or disable bot verification with DNS
     *
     * @param bool $enabled
     * @return self
     */
    public function enableBotVerification(bool $enabled): self
    {
        $this->botVerificationEnabled = $enabled;
        return $this;
    }

    /**
     * Set bot verification cache TTL
     *
     * @param int $seconds Cache TTL (3600-2592000, max 30 days)
     * @return self
     */
    public function setBotCacheTTL(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 2592000) {
            throw new \InvalidArgumentException('Bot cache TTL must be between 1h and 30 days');
        }
        $this->botCacheTTL = $seconds;
        return $this;
    }

    /**
     * Set storage backend
     *
     * @param StorageInterface $storage
     * @return self
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * Set logger instance
     *
     * @param LoggerInterface $logger
     * @return self
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Add custom threat pattern
     *
     * @param string $pattern Regex pattern
     * @param int $score Score to add (1-100)
     * @param string $description Pattern description
     * @return self
     */
    public function addThreatPattern(string $pattern, int $score, string $description = ''): self
    {
        if ($score < 1 || $score > 100) {
            throw new \InvalidArgumentException('Pattern score must be between 1 and 100');
        }
        $this->customPatterns[] = [
            'pattern' => $pattern,
            'score' => $score,
            'description' => $description,
        ];
        return $this;
    }

    /**
     * Add IP to whitelist (never ban)
     *
     * Supports both single IPs and CIDR ranges:
     * - Single IP: '192.168.1.1'
     * - CIDR range: '192.168.1.0/24', '10.0.0.0/8'
     *
     * @param string|array<int, string> $ips Single IP/CIDR or array of IPs/CIDRs
     * @return self
     */
    public function addIPWhitelist(string|array $ips): self
    {
        $ips = is_array($ips) ? $ips : [$ips];
        foreach ($ips as $ip) {
            // Check if CIDR notation
            if (strpos($ip, '/') !== false) {
                [$ipPart, $mask] = explode('/', $ip);
                if (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                    throw new \InvalidArgumentException("Invalid CIDR notation: {$ip}");
                }
                if (!is_numeric($mask) || (int)$mask < 0 || (int)$mask > 32) {
                    throw new \InvalidArgumentException("Invalid CIDR mask: {$ip}");
                }
            } else {
                // Single IP
                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                    throw new \InvalidArgumentException("Invalid IP address: {$ip}");
                }
            }
            $this->ipWhitelist[] = $ip;
        }
        return $this;
    }

    /**
     * Add IP to blacklist (always ban)
     *
     * Supports both single IPs and CIDR ranges:
     * - Single IP: '192.168.1.1'
     * - CIDR range: '192.168.1.0/24', '10.0.0.0/8'
     *
     * @param string|array<int, string> $ips Single IP/CIDR or array of IPs/CIDRs
     * @return self
     */
    public function addIPBlacklist(string|array $ips): self
    {
        $ips = is_array($ips) ? $ips : [$ips];
        foreach ($ips as $ip) {
            // Check if CIDR notation
            if (strpos($ip, '/') !== false) {
                [$ipPart, $mask] = explode('/', $ip);
                if (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                    throw new \InvalidArgumentException("Invalid CIDR notation: {$ip}");
                }
                if (!is_numeric($mask) || (int)$mask < 0 || (int)$mask > 32) {
                    throw new \InvalidArgumentException("Invalid CIDR mask: {$ip}");
                }
            } else {
                // Single IP
                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                    throw new \InvalidArgumentException("Invalid IP address: {$ip}");
                }
            }
            $this->ipBlacklist[] = $ip;
        }
        return $this;
    }

    /**
     * Set IP whitelist (replaces existing list)
     *
     * @param array<int, string> $ips Array of IPs/CIDRs
     * @return self
     */
    public function setIPWhitelist(array $ips): self
    {
        $this->ipWhitelist = [];
        return $this->addIPWhitelist($ips); // Reuse validation logic
    }

    /**
     * Set IP blacklist (replaces existing list)
     *
     * @param array<int, string> $ips Array of IPs/CIDRs
     * @return self
     */
    public function setIPBlacklist(array $ips): self
    {
        $this->ipBlacklist = [];
        return $this->addIPBlacklist($ips); // Reuse validation logic
    }

    /**
     * Enable or disable intelligence gathering
     *
     * @param bool $enabled
     * @return self
     */
    public function enableIntelligence(bool $enabled): self
    {
        $this->intelligenceEnabled = $enabled;
        return $this;
    }

    /**
     * Enable or disable critical alerts
     *
     * @param bool $enabled
     * @param string|null $webhook Webhook URL for alerts
     * @return self
     */
    public function enableAlerts(bool $enabled, ?string $webhook = null): self
    {
        $this->alertsEnabled = $enabled;
        if ($webhook) {
            if (!filter_var($webhook, FILTER_VALIDATE_URL)) {
                throw new \InvalidArgumentException('Invalid webhook URL');
            }
            $this->alertWebhook = $webhook;
        }
        return $this;
    }

    /**
     * Set environment (production, staging, development)
     *
     * @param string $environment
     * @return self
     */
    public function setEnvironment(string $environment): self
    {
        $allowed = ['production', 'staging', 'development'];
        if (!in_array($environment, $allowed)) {
            throw new \InvalidArgumentException('Environment must be: ' . implode(', ', $allowed));
        }
        $this->environment = $environment;
        return $this;
    }

    /**
     * Set rate limit maximum requests per window
     *
     * Controls how many requests a single IP can make within the rate limit window.
     * Exceeding this limit adds threat score points.
     *
     * RECOMMENDED VALUES:
     * - API endpoints: 60-100 requests/window
     * - Web applications: 100-200 requests/window
     * - High-traffic sites: 200-500 requests/window
     *
     * @param int $limit Maximum requests per window (1-10000)
     * @return self
     */
    public function setRateLimitMax(int $limit): self
    {
        if ($limit < 1 || $limit > 10000) {
            throw new \InvalidArgumentException('Rate limit must be between 1 and 10000 requests per window');
        }
        $this->rateLimitMax = $limit;
        return $this;
    }

    /**
     * Set rate limit (requests per minute) - Alias for setRateLimitMax
     *
     * @deprecated Use setRateLimitMax() instead (clearer naming)
     * @param int $limit Requests per window (1-10000)
     * @return self
     */
    public function setRateLimitPerMinute(int $limit): self
    {
        return $this->setRateLimitMax($limit);
    }

    /**
     * Set rate limit window (time window in seconds)
     *
     * Defines the time window for rate limiting.
     * Default: 60 seconds (1 minute)
     *
     * EXAMPLES:
     * - 60 seconds = per-minute rate limiting
     * - 300 seconds = per-5-minutes rate limiting
     * - 3600 seconds = per-hour rate limiting
     *
     * @param int $seconds Window size in seconds (10-3600)
     * @return self
     */
    public function setRateLimitWindow(int $seconds): self
    {
        if ($seconds < 10 || $seconds > 3600) {
            throw new \InvalidArgumentException('Rate limit window must be between 10 seconds and 1 hour');
        }
        $this->rateLimitWindow = $seconds;
        return $this;
    }

    /**
     * Set trusted proxy IPs/CIDRs
     *
     * 
     * When running behind Cloudflare, Nginx, AWS ELB, the REMOTE_ADDR is the proxy IP.
     * Configure trusted proxies to extract real client IP from X-Forwarded-For headers.
     *
     * SECURITY: Only proxy headers from these IPs are trusted (prevents IP spoofing).
     *
     * SUPPORTED FORMATS:
     * - Single IP: '192.168.1.1'
     * - CIDR notation: '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
     *
     * COMMON EXAMPLES:
     * - Cloudflare: See https://www.cloudflare.com/ips/ (use CIDR ranges)
     * - AWS ELB: Use VPC CIDR range
     * - Local Nginx: ['127.0.0.1', '::1']
     * - Docker network: ['172.17.0.0/16']
     *
     * @param array<int, string> $proxies List of trusted proxy IPs/CIDRs
     * @return self
     */
    public function setTrustedProxies(array $proxies): self
    {
        // Validate each proxy IP/CIDR
        foreach ($proxies as $proxy) {
            if (!is_string($proxy)) {
                throw new \InvalidArgumentException('Trusted proxies must be strings (IP or CIDR)');
            }

            // Check if CIDR notation
            if (strpos($proxy, '/') !== false) {
                [$ip, $mask] = explode('/', $proxy);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                    throw new \InvalidArgumentException("Invalid CIDR notation: {$proxy}");
                }
                if (!is_numeric($mask) || (int)$mask < 0 || (int)$mask > 32) {
                    throw new \InvalidArgumentException("Invalid CIDR mask: {$proxy}");
                }
            } else {
                // Single IP
                if (filter_var($proxy, FILTER_VALIDATE_IP) === false) {
                    throw new \InvalidArgumentException("Invalid IP address: {$proxy}");
                }
            }
        }

        $this->trustedProxies = $proxies;
        return $this;
    }


    /**
     * Create config from array (Laravel/Symfony style)
     *
     * @param array<string, mixed> $config Configuration array
     * @return self
     */
    public static function fromArray(array $config): self
    {
        $instance = new self();

        if (isset($config['score_threshold']) && is_int($config['score_threshold'])) {
            $instance->setScoreThreshold($config['score_threshold']);
        }
        if (isset($config['ban_duration']) && is_int($config['ban_duration'])) {
            $instance->setBanDuration($config['ban_duration']);
        }
        if (isset($config['tracking_window']) && is_int($config['tracking_window'])) {
            $instance->setTrackingWindow($config['tracking_window']);
        }
        if (isset($config['honeypot_ban_duration']) && is_int($config['honeypot_ban_duration'])) {
            $instance->setHoneypotBanDuration($config['honeypot_ban_duration']);
        }
        if (isset($config['honeypot_enabled']) && is_bool($config['honeypot_enabled'])) {
            $instance->enableHoneypot($config['honeypot_enabled']);
        }
        if (isset($config['bot_verification_enabled']) && is_bool($config['bot_verification_enabled'])) {
            $instance->enableBotVerification($config['bot_verification_enabled']);
        }
        if (isset($config['bot_cache_ttl']) && is_int($config['bot_cache_ttl'])) {
            $instance->setBotCacheTTL($config['bot_cache_ttl']);
        }
        if (isset($config['storage']) && $config['storage'] instanceof StorageInterface) {
            $instance->setStorage($config['storage']);
        }
        if (isset($config['logger']) && $config['logger'] instanceof LoggerInterface) {
            $instance->setLogger($config['logger']);
        }
        if (isset($config['ip_whitelist']) && (is_string($config['ip_whitelist']) || is_array($config['ip_whitelist']))) {
            $instance->addIPWhitelist($config['ip_whitelist']);
        }
        if (isset($config['ip_blacklist']) && (is_string($config['ip_blacklist']) || is_array($config['ip_blacklist']))) {
            $instance->addIPBlacklist($config['ip_blacklist']);
        }
        if (isset($config['intelligence_enabled']) && is_bool($config['intelligence_enabled'])) {
            $instance->enableIntelligence($config['intelligence_enabled']);
        }
        if (isset($config['alerts_enabled']) && is_bool($config['alerts_enabled'])) {
            $webhook = isset($config['alert_webhook']) && is_string($config['alert_webhook']) ? $config['alert_webhook'] : null;
            $instance->enableAlerts($config['alerts_enabled'], $webhook);
        }
        if (isset($config['environment']) && is_string($config['environment'])) {
            $instance->setEnvironment($config['environment']);
        }
        if (isset($config['rate_limit_per_minute']) && is_int($config['rate_limit_per_minute'])) {
            $instance->setRateLimitPerMinute($config['rate_limit_per_minute']);
        }
        if (isset($config['rate_limit_window']) && is_int($config['rate_limit_window'])) {
            $instance->setRateLimitWindow($config['rate_limit_window']);
        }
        if (isset($config['trusted_proxies']) && is_array($config['trusted_proxies'])) {
            $instance->setTrustedProxies($config['trusted_proxies']);
        }
        if (isset($config['blocked_countries']) && is_array($config['blocked_countries'])) {
            $instance->setBlockedCountries($config['blocked_countries']);
        }
        if (isset($config['geoip_enabled']) && is_bool($config['geoip_enabled'])) {
            $instance->enableGeoIP($config['geoip_enabled']);
        }
        if (isset($config['geoip_cache_ttl']) && is_int($config['geoip_cache_ttl'])) {
            $instance->setGeoIPCacheTTL($config['geoip_cache_ttl']);
        }
        if (isset($config['geoip_ban_duration']) && is_int($config['geoip_ban_duration'])) {
            $instance->setGeoIPBanDuration($config['geoip_ban_duration']);
        }
        if (isset($config['custom_patterns']) && is_array($config['custom_patterns'])) {
            foreach ($config['custom_patterns'] as $pattern) {
                if (is_array($pattern) && isset($pattern['pattern'], $pattern['score'])) {
                    $instance->addThreatPattern(
                        $pattern['pattern'],
                        $pattern['score'],
                        $pattern['description'] ?? ''
                    );
                }
            }
        }

        return $instance;
    }

    // Getters

    public function getScoreThreshold(): int { return $this->scoreThreshold; }
    public function getBanDuration(): int { return $this->banDuration; }
    public function getTrackingWindow(): int { return $this->trackingWindow; }
    public function getHoneypotBanDuration(): int { return $this->honeypotBanDuration; }
    public function isHoneypotEnabled(): bool { return $this->honeypotEnabled; }
    public function isBotVerificationEnabled(): bool { return $this->botVerificationEnabled; }
    public function getBotCacheTTL(): int { return $this->botCacheTTL; }
    public function getStorage(): ?StorageInterface { return $this->storage; }
    public function getLogger(): ?LoggerInterface { return $this->logger; }
    /** @return array<int, array{pattern: string, score: int, description: string}> */
    public function getCustomPatterns(): array { return $this->customPatterns; }
    /** @return array<int, string> */
    public function getIPWhitelist(): array { return $this->ipWhitelist; }
    /** @return array<int, string> */
    public function getIPBlacklist(): array { return $this->ipBlacklist; }
    public function isIntelligenceEnabled(): bool { return $this->intelligenceEnabled; }
    public function isAlertsEnabled(): bool { return $this->alertsEnabled; }
    public function getAlertWebhook(): ?string { return $this->alertWebhook; }
    public function getEnvironment(): string { return $this->environment; }
    /**
     * Get max requests per rate limit window
     *
     * @deprecated Use getRateLimitMax() instead (clearer naming)
     * @return int Max requests allowed
     */
    public function getRateLimitPerMinute(): int { return $this->rateLimitMax; }

    /** @return int Max requests per window */
    public function getRateLimitMax(): int { return $this->rateLimitMax; }
    public function getRateLimitWindow(): int { return $this->rateLimitWindow; }
    /** @return array<int, string> */
    public function getTrustedProxies(): array { return $this->trustedProxies; }
    /** @return array<int, string> */
    public function getBlockedCountries(): array { return $this->blockedCountries; }
    public function isGeoIPEnabled(): bool { return $this->geoipEnabled; }
    public function getGeoIPCacheTTL(): int { return $this->geoipCacheTTL; }
    public function getGeoIPBanDuration(): int { return $this->geoipBanDuration; }
    public function isFailClosedEnabled(): bool { return $this->failClosed; }

    /**
     * Set blocked countries (ISO 3166-1 alpha-2 codes)
     *
     * @param array<int, string> $countries Country codes (e.g., ['CN', 'RU', 'KP'])
     * @return self
     */
    public function setBlockedCountries(array $countries): self
    {
        foreach ($countries as $code) {
            if (!is_string($code) || strlen($code) !== 2) {
                throw new \InvalidArgumentException("Invalid country code: {$code}. Must be ISO 3166-1 alpha-2 (2 letters)");
            }
        }
        $this->blockedCountries = array_map('strtoupper', $countries);
        return $this;
    }

    /**
     * Enable GeoIP detection
     *
     * @param bool $enabled
     * @return self
     */
    public function enableGeoIP(bool $enabled): self
    {
        $this->geoipEnabled = $enabled;
        return $this;
    }

    /**
     * Set GeoIP cache TTL
     *
     * @param int $seconds Cache TTL (3600-604800, 1h-7days)
     * @return self
     */
    public function setGeoIPCacheTTL(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 604800) {
            throw new \InvalidArgumentException('GeoIP cache TTL must be between 1 hour and 7 days');
        }
        $this->geoipCacheTTL = $seconds;
        return $this;
    }

    /**
     * Enable fail-closed mode (block traffic on storage failure)
     *
     * FAIL-OPEN (false, default):
     * - Storage unavailable → Allow traffic (prioritize availability)
     *
     * FAIL-CLOSED (true):
     * - Storage unavailable → Block traffic (prioritize security)
     *
     * @param bool $enabled Enable fail-closed mode
     * @return self
     */
    public function setFailClosed(bool $enabled): self
    {
        $this->failClosed = $enabled;
        return $this;
    }

    /**
     * Set GeoIP ban duration
     *
     * @param int $seconds Ban duration (3600-2592000, 1h-30days)
     * @return self
     */
    public function setGeoIPBanDuration(int $seconds): self
    {
        if ($seconds < 3600 || $seconds > 2592000) {
            throw new \InvalidArgumentException('GeoIP ban duration must be between 1 hour and 30 days');
        }
        $this->geoipBanDuration = $seconds;
        return $this;
    }
}
