<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Services;

use Senza1dio\SecurityShield\Utils\IPUtils;
use Senza1dio\SecurityShield\Services\FrameworkDetector;

/**
 * Threat Pattern Detection - Static Pattern Matching
 *
 * Framework-agnostic threat pattern database for basic vulnerability scanning detection.
 *
 * WHAT THIS IS:
 * - Static regex patterns for common attacks (SQLi, XSS, path scanning)
 * - Path-based honeypot detection (/.env, /.git, /wp-admin)
 * - User-Agent fingerprinting (scanners, bots, fake browsers)
 * - Simple scoring system (accumulate points → ban)
 *
 * WHAT THIS IS NOT:
 * - WAF-grade detection (no context-aware parsing)
 * - Machine learning / adaptive detection
 * - DDoS protection (rate limiting only)
 * - Zero-day exploit detection
 *
 * LIMITATIONS:
 * - False positives possible (generic regex)
 * - False negatives likely (static patterns, no evasion handling)
 * - No DOM-aware XSS detection
 * - No SQL syntax parsing
 * - Spoofable bot User-Agents (DNS verification required)
 *
 * MAINTENANCE REQUIRED:
 * - Static lists (bots, IPs, UAs) must be updated manually
 * - Bot User-Agent patterns degrade over time (new bots, UA changes)
 * - OpenAI IP ranges change (check https://openai.com/api/security/ip-ranges/)
 * - Scanner tools evolve (new tools, updated UAs)
 * - Without updates, detection effectiveness degrades
 * - Recommended: Review lists quarterly, update annually minimum
 *
 * USE CASES:
 * - Deterrence against automated scanners
 * - Basic bot filtering
 * - Honeypot trapping
 * - Logging suspicious behavior
 *
 * NOT FOR:
 * - Sole security layer (use real WAF: Cloudflare, ModSecurity)
 * - Protection against skilled attackers
 *
 * @package Senza1dio\SecurityShield\Services
 * @version 1.2.0
 * @author Security Team
 * @license MIT
 */
class ThreatPatterns
{
    /**
     * Score threshold for auto-ban (50 points)
     */
    public const SCORE_THRESHOLD = 50;

    /**
     * Default ban duration in seconds (24 hours)
     */
    public const BAN_DURATION = 86400;

    /**
     * Tracking window for score accumulation (1 hour)
     */
    public const TRACKING_WINDOW = 3600;

    /**
     * Score values for different threat types
     */
    public const SCORE_CRITICAL_PATH = 30;      // Increased from 20 for phpinfo.php security
    public const SCORE_CMS_PATH = 15;
    public const SCORE_CONFIG_PATH = 10;
    public const SCORE_SCANNER_USER_AGENT = 30;
    public const SCORE_FAKE_USER_AGENT = 50;
    public const SCORE_NULL_USER_AGENT = 100;   // Instant ban
    public const SCORE_GEO_BLOCKED = 50;
    public const SCORE_UNICODE_OBFUSCATION = 20;
    public const SCORE_RATE_LIMIT_EXCEEDED = 20; // Rate limit violation

    /**
     * Critical vulnerability paths - HIGH SCORE (30 points)
     *
     * These paths indicate clear vulnerability scanning attempts.
     * Accessing these paths is NEVER legitimate for normal users.
     *
     * Categories:
     * - Environment files (.env, .env.local, .env.production)
     * - Version control (.git/, .svn/, .hg/)
     * - Config files (config.php, database.yml)
     * - Cloud credentials (.aws/credentials, aws_access_keys.json)
     * - SSH keys (.ssh/, id_rsa)
     * - Database dumps (backup.sql, dump.sql)
     * - Admin password files (.htpasswd)
     * - Debug scripts (phpinfo.php, info.php, test.php)
     * - Shell backdoors (shell.php, c99.php, r57.php)
     */
    private const CRITICAL_PATHS = [
        // Environment files
        '/.env',
        '/.env.local',
        '/.env.production',

        // Version control systems
        '/.git/',
        '/.git/config',
        '/.svn/',
        '/.hg/',

        // PHP config files
        '/config.php',
        '/configuration.php',
        '/settings.php',
        '/database.yml',
        '/database.php',

        // AWS credentials (cloud keys)
        '/.aws/',
        '/.aws/credentials',
        '/.aws/config',
        '/aws/credentials',
        '/aws/config',
        '/aws_lambda_config.json',
        '/aws/aws_config.json',
        '/aws_access_keys.json',

        // SSH keys
        '/.ssh/',
        '/id_rsa',
        '/id_rsa.pub',

        // Database dumps
        '/backup.sql',
        '/dump.sql',

        // Apache auth files
        '/.htpasswd',

        // Debug/info scripts
        '/phpinfo.php',
        '/info.php',
        '/test.php',

        // Shell backdoors
        '/shell.php',
        '/c99.php',
        '/r57.php',
    ];

    /**
     * WordPress/CMS scanning paths - MEDIUM-HIGH SCORE (15 points)
     *
     * These paths indicate CMS vulnerability scanning (WordPress, Joomla, Drupal, etc.).
     * Common targets for automated scanners looking for outdated CMS installations.
     *
     * Categories:
     * - WordPress (/wp-admin, /wp-login.php, /wp-config.php)
     * - Joomla (/administrator/, /joomla/)
     * - Drupal (/drupal/)
     * - Magento (/magento/)
     * - PrestaShop (/prestashop/)
     * - TYPO3 (/typo3/)
     * - Generic admin panels (/admin/)
     * - Database tools (/adminer.php, /phpmyadmin/, /pgadmin/)
     */
    private const CMS_PATHS = [
        // WordPress
        '/wp-admin/',
        '/wp-login.php',
        '/wp-content/',
        '/wp-includes/',
        '/wp-config.php',

        // Joomla
        '/administrator/',
        '/joomla/',

        // Drupal
        '/drupal/',

        // Magento
        '/magento/',

        // PrestaShop
        '/prestashop/',

        // TYPO3
        '/typo3/',

        // Generic admin
        '/admin/',

        // Database admin tools
        '/adminer.php',
        '/phpmyadmin/',
        '/pma/',
        '/mysql/',
        '/postgres/',
        '/postgresql/',
        '/pgadmin/',
    ];

    /**
     * Config file scanning paths - MEDIUM SCORE (10 points)
     *
     * These paths indicate configuration file enumeration attempts.
     * Attackers search for config files to discover credentials, API keys, or system info.
     *
     * Categories:
     * - JSON configs (config.json, app.json, package.json)
     * - YAML configs (config.yml, docker-compose.yml, kubernetes.yml)
     * - Package managers (composer.json, composer.lock, .npmrc, .yarnrc)
     * - Docker/containers (Dockerfile, .dockerignore)
     * - Secrets (secrets.json, credentials.json)
     */
    private const CONFIG_PATHS = [
        // JSON configs
        '/config.json',
        '/app.json',
        '/package.json',
        '/composer.json',
        '/composer.lock',
        '/secrets.json',
        '/credentials.json',

        // YAML configs
        '/config.yml',
        '/docker-compose.yml',
        '/kubernetes.yml',

        // Package manager configs
        '/.npmrc',
        '/.yarnrc',

        // Docker
        '/Dockerfile',
        '/.dockerignore',
    ];

    /**
     * Known scanner User-Agents - CRITICAL SCORE (30 points)
     *
     * These User-Agent strings are NEVER legitimate for normal browsing.
     * They identify automated vulnerability scanners, penetration testing tools,
     * and security research tools.
     *
     * Categories:
     * - SQL injection tools (sqlmap, havij)
     * - Web scanners (nikto, w3af, skipfish, grabber)
     * - Network scanners (nmap, masscan, zmap)
     * - Vulnerability scanners (nessus, openvas, acunetix, netsparker)
     * - Exploitation frameworks (metasploit)
     * - Fuzzing tools (wfuzz, ffuf)
     * - CMS scanners (wpscan, joomscan)
     * - Directory bruteforcers (dirbuster, dirb, gobuster)
     * - Password crackers (hydra, medusa)
     * - Internet scanners (zgrab, shodan, censys)
     */
    private const SCANNER_USER_AGENTS = [
        // SQL injection tools
        'sqlmap',
        'havij',

        // Web vulnerability scanners
        'nikto',
        'w3af',
        'skipfish',
        'grabber',

        // Network scanners
        'nmap',
        'masscan',
        'zmap',

        // Professional vulnerability scanners
        'nessus',
        'openvas',
        'acunetix',
        'netsparker',
        'burpsuite',

        // Exploitation frameworks
        'metasploit',

        // CMS scanners
        'wpscan',
        'joomscan',

        // Directory bruteforcers
        'dirbuster',
        'dirb',
        'gobuster',

        // Fuzzing tools
        'ffuf',
        'wfuzz',

        // Password crackers
        'hydra',
        'medusa',

        // Internet-wide scanners
        'zgrab',
        'shodan',
        'censys',
    ];

    /**
     * Legitimate Bot User-Agents (DNS VERIFICATION REQUIRED)
     *
     * CRITICAL SECURITY WARNING (2025-01-23):
     * User-Agent matching ALONE is INSECURE and easily spoofed.
     *
     * This list is used ONLY for DNS verification candidates.
     * If UA matches this list, we perform reverse DNS + forward DNS verification.
     * Without DNS verification, UA match means NOTHING.
     *
     * REMOVED FROM LIST (too easy to spoof, no DNS verification possible):
     * - postman, insomnia → developer tools (anyone can set this UA)
     * - whatsapp, discord → messaging apps (no official bot verification)
     * - curl, wget → command-line tools (trivially spoofable)
     * - Generic monitoring tools → often don't have verifiable DNS
     *
     * KEPT IN LIST (have official DNS verification):
     * - Search engines (Google, Bing, Yandex, Baidu)
     * - Major social media (Facebook, Twitter, LinkedIn)
     * - Performance tools with verified IPs (Lighthouse, GTmetrix)
     * - AI crawlers with IP ranges (OpenAI, Anthropic)
     *
     * Categories:
     * - Search engines (DNS verifiable)
     * - Performance testing (DNS verifiable)
     * - AI crawlers (DNS or IP range verifiable)
     * - Social media (DNS verifiable)
     * - SEO tools (DNS verifiable)
     * - Monitoring (DNS verifiable)
     */
    private const LEGITIMATE_BOTS = [
        // Search Engine Crawlers (Google)
        'googlebot',
        'googlebot-image',
        'googlebot-video',
        'googlebot-news',
        'google-inspectiontool',
        'google-extended',          // Google Bard / Vertex AI (2025)
        'google-safety',            // Google Safe Browsing
        'storebot-google',
        'adsbot-google',
        'mediapartners-google',

        // Performance Testing Tools (CRITICAL for PageSpeed!)
        'chrome-lighthouse',
        'lighthouse',
        'gtmetrix',
        'webpagetest',
        // NOTE: pingdom moved to Monitoring section (duplicate removed)

        // Other Search Engines
        'bingbot',
        'msnbot',
        'slurp',                    // Yahoo
        'duckduckbot',
        'baiduspider',              // Baidu (China)
        'yandexbot',                // Yandex (Russia)
        'sogou',                    // Sogou (China)
        'exabot',                   // Exalead (France)
        'seznambot',                // Seznam.cz (Czech Republic)

        // AI Crawlers (2025)
        'gptbot',                   // OpenAI GPTBot
        'chatgpt-user',             // OpenAI ChatGPT-User (live browsing)
        'oai-searchbot',            // OpenAI SearchGPT
        'claudebot',                // Anthropic Claude
        'anthropic-ai',
        'claude-web',
        'perplexitybot',            // Perplexity AI
        'cohere-ai',                // Cohere AI

        // Social Media Crawlers (DNS verifiable only)
        'facebookexternalhit',
        'facebookcatalog',
        'telegrambot',              // MUST be before twitterbot (UA contains "like TwitterBot")
        'twitterbot',
        'linkedinbot',
        'pinterestbot',
        'skypeuripreview',
        // REMOVED: whatsapp, discordbot, reddit, slackbot
        // REASON: No reliable reverse DNS, easily spoofed, too generic

        // Mobile App Crawlers
        'applebot',
        'googlebot-mobile',

        // Monitoring & Analytics
        'uptimerobot',
        'pingdom',                  // NOTE: Only listed here (removed from Performance Tools duplicate)
        'statuscake',
        'hetrixtools',
        'newrelicsynthetics',
        'datadog',

        // SEO & Website Tools
        'semrushbot',
        'ahrefsbot',
        'mj12bot',                  // Majestic SEO
        'dotbot',                   // Moz SEO
        'rogerbot',                 // Moz SEO (legacy)
        'screaming frog',
        'trendictionbot',           // Trendiction SEO (Germany)

        // Archive & Research
        'ia_archiver',              // Internet Archive (Wayback Machine)
        'archive.org_bot',
        'ccbot',                    // Common Crawl
        'netcraftsurveyagent',

        // News & RSS Aggregators
        'feedly',
        'flipboard',
        'newsblur',

        // REMOVED SECTION: Developer Tools
        // 'postman', 'insomnia' - Easily spoofed, no DNS verification
        // Anyone can set UA to "Postman" → bypass all checks
        // If you need to whitelist these, use IP whitelist instead

        // Commercial Bots
        'amazonadbot',
        'amazonbot',                // Amazon/Alexa Crawler
        'bytespider',               // TikTok/ByteDance
        'petalbot',                 // Huawei Search

        // Media Monitoring
        'mediatoolkitbot',          // Mediatoolkit/Determ
    ];

    /**
     * Fake/Obsolete User-Agents - HIGH SCORE (50 points)
     *
     * REALITY CHECK (2025-01-23):
     * "Impossible" is WRONG. These are IMPROBABLE but not impossible.
     *
     * LEGITIMATE USE CASES FOR OLD BROWSERS:
     * - Corporate environments with frozen IT policies
     * - Embedded devices (smart TVs, IoT, industrial systems)
     * - WebView apps on old Android/iOS devices
     * - Legacy software with embedded browsers
     * - Government/military systems with slow update cycles
     *
     * REVISED LOGIC:
     * - IE 9/10: Very improbable (EOL 2016), likely fake
     * - Chrome/Firefox < 80: Possible on old devices, not instant ban
     * - Known bot tools: High confidence (HTTrack, WebStripper, etc.)
     * - Ancient Windows: Possible in industrial/embedded contexts
     *
     * FALSE POSITIVE RISK: Medium (old devices exist)
     * FALSE NEGATIVE RISK: Low (catches most bots)
     * TRADE-OFF: Don't break legitimate edge cases
     *
     * Categories:
     * - IE 6-10 (extremely rare, high confidence fake)
     * - Known download/scraper tools (high confidence)
     * - Ancient Windows 98/2000 (very rare, medium confidence)
     */
    private const FAKE_USER_AGENTS = [
        // Internet Explorer 6-10 (extremely rare in 2025)
        'MSIE 6.0',
        'MSIE 7.0',
        'MSIE 8.0',
        'MSIE 9.0',
        'MSIE 10.0',
        // NOTE: IE11/Trident REMOVED - still used in corporate environments

        // Chrome < 70 (VERY old, but possible on old devices)
        // NOTE: Chrome 70-99 REMOVED - possible on embedded devices
        'Chrome/60.0',
        'Chrome/50.0',
        'Chrome/40.0',

        // Firefox < 60 (VERY old)
        // NOTE: Firefox 60-99 REMOVED - possible on old systems
        'Firefox/50.0',
        'Firefox/40.0',
        'Firefox/30.0',

        // Safari < 10 (iOS 9 and earlier)
        'Safari/9.0',
        'Safari/8.0',

        // Known scraper/downloader tools (HIGH CONFIDENCE)
        'NCLIENT',
        'WebStripper',
        'WebCopier',
        'Offline Explorer',
        'HTTrack',
        'Teleport',
        'WebZIP',
        'FlashGet',
        'Go-http-client',

        // NOTE: curl/wget removed from fake list
        // REASON: Legitimate monitoring tools (curl-based health checks, wget cron jobs)
        // IF YOU WANT TO BLOCK: Add to IP blacklist or custom patterns, NOT here
        // Marking as "fake" causes false positives for legitimate automation

        // Ancient Windows (98/2000 extremely rare)
        'Windows 98',
        'Windows NT 5.0',           // Windows 2000
        // NOTE: Windows XP/Vista REMOVED - still exist in some environments
    ];

    /**
     * Geo-blocked Countries - AUTO-BAN (50 points)
     *
     * REALITY CHECK (2025-01-23):
     * This is a POLITICAL decision, not a pure security measure.
     *
     * RATIONALE:
     * - High volume of scanning/attack traffic observed from these regions
     * - NOT because "all users from these countries are malicious"
     * - Trade-off: Block attack volume vs lose legitimate users
     *
     * LIMITATIONS:
     * - VPN/proxy users can bypass
     * - Legitimate users from these countries are blocked
     * - Not a substitute for proper security (WAF, rate limiting, etc.)
     *
     * EXCEPTIONS:
     * - Legitimate bots (Googlebot, Yandex, Baidu) bypass geo-blocking
     * - Whitelisted IPs bypass geo-blocking
     */
    private const BLOCKED_COUNTRIES = [
        'RU',  // Russia (high attack volume observed)
        'CN',  // China (high attack volume observed)
        'KP',  // North Korea (state infrastructure concerns)
    ];

    /**
     * Legitimate Bot Hostname Suffixes for DNS Verification
     *
     * HOW IT WORKS:
     * 1. Check User-Agent contains bot name
     * 2. Reverse DNS lookup: IP → hostname
     * 3. Verify hostname ends with legitimate suffix
     * 4. Forward DNS lookup: hostname → IP (must match original)
     * 5. Cache result in Redis (24h) to avoid repeated DNS calls
     *
     * SOURCE: Official bot documentation from each service
     *
     * @var array<string, string[]> Bot name => Allowed hostname suffixes
     */
    private const LEGITIMATE_BOT_HOSTNAMES = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'google-safety' => ['.googlebot.com', '.google.com'],
        'bingbot' => ['.search.msn.com'],
        'slurp' => ['.crawl.yahoo.net'],
        'duckduckbot' => ['.duckduckgo.com'],
        'baiduspider' => ['.crawl.baidu.com', '.crawl.baidu.jp'],
        'yandexbot' => ['.yandex.com', '.yandex.net', '.yandex.ru'],
        'facebookexternalhit' => ['.facebook.com', '.fbcdn.net', '.fbsv.net', '.akamaitechnologies.com'],
        'twitterbot' => ['.twttr.com', '.akamaitechnologies.com'],
        'telegrambot' => ['.telegram.org'],
        'linkedinbot' => ['.linkedin.com'],
        'pinterestbot' => ['.pinterest.com'],
        'applebot' => ['.applebot.apple.com'],
        'ia_archiver' => ['.archive.org'],
        'amazonbot' => ['.crawl.amazonbot.amazon'],
    ];

    /**
     * OpenAI IP Ranges for ChatGPT-User, GPTBot, OAI-SearchBot
     *
     * OpenAI crawlers use Azure IPs without reverse DNS, so we verify by IP range.
     * These are /28 CIDR blocks (16 IPs each).
     *
     * SOURCE: https://openai.com/chatgpt-user.json (official)
     * UPDATED: 2025-12-15 (creationTime: 2025-12-12)
     *
     * @var string[] CIDR notation IP ranges
     */
    private const OPENAI_IP_RANGES = [
        // 104.x.x.x
        '104.210.139.192/28', '104.210.139.224/28',

        // 13.x.x.x
        '13.65.138.112/28', '13.65.138.96/28', '13.67.46.240/28', '13.67.72.16/28',
        '13.70.107.160/28', '13.71.2.208/28', '13.76.115.224/28', '13.76.115.240/28',
        '13.76.116.80/28', '13.76.223.48/28', '13.76.32.208/28', '13.79.43.0/28',
        '13.83.167.128/28', '13.83.237.176/28',

        // 132.x - 138.x
        '132.196.82.48/28', '135.119.134.128/28', '135.119.134.192/28',
        '135.237.131.208/28', '135.237.133.112/28', '135.237.133.48/28',
        '137.135.183.96/28', '137.135.190.240/28', '137.135.191.176/28', '137.135.191.32/28',
        '138.91.30.48/28', '138.91.46.96/28',

        // 168.x - 172.x
        '168.63.252.240/28', '172.178.140.144/28', '172.178.141.112/28', '172.178.141.128/28',
        '172.183.143.224/28', '172.183.222.128/28', '172.204.16.64/28', '172.212.159.64/28',
        '172.213.11.144/28', '172.213.12.112/28', '172.213.21.112/28', '172.213.21.144/28',
        '172.213.21.16/28',

        // 191.x.x.x (Brazil Azure)
        '191.233.194.32/28', '191.233.196.112/28', '191.233.199.160/28', '191.234.167.128/28',
        '191.235.66.16/28', '191.235.98.144/28', '191.235.99.80/28', '191.237.249.64/28',
        '191.239.245.16/28',

        // 20.x.x.x (Azure main)
        '20.0.53.96/28', '20.102.212.144/28', '20.117.22.224/28', '20.125.112.224/28',
        '20.125.144.144/28', '20.161.75.208/28', '20.168.7.192/28', '20.168.7.240/28',
        '20.169.72.112/28', '20.169.72.96/28', '20.169.73.176/28', '20.169.73.32/28',
        '20.169.73.64/28', '20.169.78.112/28', '20.169.78.128/28', '20.169.78.144/28',
        '20.169.78.160/28', '20.169.78.176/28', '20.169.78.192/28', '20.169.78.48/28',
        '20.169.78.64/28', '20.169.78.80/28', '20.169.78.96/28', '20.172.29.32/28',
        '20.193.50.32/28', '20.194.0.208/28', '20.194.1.0/28', '20.194.157.176/28',
        '20.198.67.96/28', '20.204.24.240/28', '20.210.154.128/28', '20.210.174.208/28',
        '20.210.211.192/28', '20.215.187.208/28', '20.215.188.192/28', '20.215.214.16/28',
        '20.215.219.128/28', '20.215.219.160/28', '20.215.219.208/28', '20.227.140.32/28',
        '20.228.106.176/28', '20.235.75.208/28', '20.235.87.224/28', '20.249.63.208/28',
        '20.27.94.128/28', '20.45.178.144/28', '20.55.229.144/28', '20.63.221.64/28',
        '20.90.7.144/28', '20.97.189.96/28',

        // 23.x.x.x
        '23.102.140.144/28', '23.102.141.32/28', '23.97.109.224/28', '23.98.142.176/28',
        '23.98.179.16/28', '23.98.186.176/28', '23.98.186.192/28', '23.98.186.64/28',
        '23.98.186.96/28',

        // 4.x.x.x
        '4.151.119.48/28', '4.151.241.240/28', '4.151.71.176/28', '4.196.118.112/28',
        '4.196.198.80/28', '4.197.115.112/28', '4.197.19.176/28', '4.197.22.112/28',
        '4.197.64.0/28', '4.197.64.16/28', '4.197.64.48/28', '4.197.64.64/28',
        '4.205.128.176/28',

        // 40.x.x.x
        '40.116.73.208/28', '40.75.14.224/28', '40.81.234.144/28', '40.84.181.32/28',
        '40.84.221.208/28', '40.84.221.224/28',

        // 51.x.x.x
        '51.8.155.112/28', '51.8.155.48/28', '51.8.155.64/28', '51.8.155.80/28',

        // 52.x.x.x
        '52.148.129.32/28', '52.154.22.48/28', '52.156.77.144/28', '52.159.227.32/28',
        '52.159.249.96/28', '52.172.129.160/28', '52.173.123.0/28', '52.173.219.112/28',
        '52.173.219.96/28', '52.173.234.16/28', '52.173.234.80/28', '52.173.235.80/28',
        '52.176.139.176/28', '52.187.246.128/28', '52.190.137.144/28', '52.190.137.16/28',
        '52.190.139.48/28', '52.190.142.64/28', '52.190.190.16/28', '52.225.75.208/28',
        '52.230.163.32/28', '52.230.164.176/28', '52.231.30.48/28', '52.231.34.176/28',
        '52.231.39.144/28', '52.231.39.192/28', '52.231.49.48/28', '52.231.50.64/28',
        '52.236.94.144/28', '52.242.132.224/28', '52.242.132.240/28', '52.242.245.208/28',
        '52.252.113.240/28', '52.255.109.112/28', '52.255.109.128/28', '52.255.109.144/28',
        '52.255.109.80/28', '52.255.109.96/28', '52.255.111.0/28', '52.255.111.112/28',
        '52.255.111.16/28', '52.255.111.32/28', '52.255.111.48/28', '52.255.111.80/28',

        // 57.x - 74.x
        '57.154.174.112/28', '57.154.175.0/28', '57.154.187.32/28',
        '68.154.28.96/28', '68.218.30.112/28', '68.220.57.64/28', '68.221.67.160/28',
        '68.221.67.192/28', '68.221.67.224/28', '68.221.67.240/28', '68.221.75.16/28',
        '74.226.253.160/28', '74.249.86.176/28', '74.7.35.112/28', '74.7.35.48/28',
        '74.7.36.64/28', '74.7.36.80/28', '74.7.36.96/28',
    ];

    // ============================================================================
    // PATH CHECKING METHODS
    // ============================================================================

    /**
     * Check if path matches critical vulnerability patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches critical patterns
     */
    public static function isCriticalPath(string $path): bool
    {
        return self::matchesPaths($path, self::CRITICAL_PATHS);
    }

    /**
     * Check if path matches CMS scanning patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches CMS patterns
     */
    public static function isCMSPath(string $path): bool
    {
        // IMPORTANT: Framework detection bypass
        // If FrameworkDetector identifies path as legitimate for current framework,
        // we skip CMS honeypot detection to prevent false positives.
        //
        // LIMITATION: If FrameworkDetector fails or misdetects, legitimate paths
        // could trigger honeypot. This is a trade-off for security over availability.
        //
        // RECOMMENDATION: Always whitelist admin IPs for CMS sites.
        if (FrameworkDetector::isLegitimateFrameworkPath($path)) {
            return false; // Legitimate framework path - not a honeypot
        }

        return self::matchesPaths($path, self::CMS_PATHS);
    }

    /**
     * Check if path matches config file patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches config patterns
     */
    public static function isConfigPath(string $path): bool
    {
        return self::matchesPaths($path, self::CONFIG_PATHS);
    }

    /**
     * Generic path matching helper
     *
     * Supports both exact matches and prefix/contains matching.
     *
     * @param string $path Request path to check
     * @param array<string> $patterns Array of patterns to match against
     * @return bool True if path matches any pattern
     */
    /**
     * Check if path matches any pattern
     *
     * AGGRESSIVE MATCHING (2025-01-23):
     * Uses exact + starts_with + contains matching.
     *
     * FALSE POSITIVE RISK:
     * - /api/v1/user/.env/avatar.png → matches /.env (CRITICAL)
     * - /docs/wp-admin-guide.html → matches /wp-admin (CMS)
     * - Not impossible in modern apps (CDN paths, dynamic routes)
     *
     * TRADE-OFF:
     * - Higher false positive risk
     * - Catches more evasion attempts (/.env/../../config)
     * - Better scanner detection
     *
     * IF FALSE POSITIVES OCCUR:
     * - Use IP whitelist for known good sources
     * - Add path to whitelist in custom patterns
     * - Or switch to exact-match-only mode
     *
     * @param string $path Request path
     * @param array<int, string> $patterns Patterns to match
     * @return bool True if matches any pattern
     */
    private static function matchesPaths(string $path, array $patterns): bool
    {
        $pathLower = strtolower($path);

        // Pre-compute lowercase patterns outside loop for performance
        static $patternCache = [];
        $cacheKey = md5(implode('|', $patterns));

        if (!isset($patternCache[$cacheKey])) {
            $patternCache[$cacheKey] = array_map('strtolower', $patterns);
        }

        $lowercasePatterns = $patternCache[$cacheKey];

        foreach ($lowercasePatterns as $patternLower) {
            // Exact match
            if ($pathLower === $patternLower) {
                return true;
            }

            // Prefix match (path starts with pattern)
            if (str_starts_with($pathLower, $patternLower)) {
                return true;
            }

            // Segment match: Pattern must match a path segment boundary
            // This prevents /api/v1/user/.env/avatar.png from matching /.env
            // But allows /.env and /.env.local to match
            if (str_contains($patternLower, '.')) {
                // For file patterns like /.env, only match at start or after /
                $position = strpos($pathLower, $patternLower);
                if ($position !== false) {
                    // Must be at start or preceded by /
                    if ($position === 0 || $pathLower[$position - 1] === '/') {
                        // Must be at end or followed by / or end of string
                        $afterPattern = $position + strlen($patternLower);
                        if ($afterPattern >= strlen($pathLower) ||
                            $pathLower[$afterPattern] === '/' ||
                            $pathLower[$afterPattern] === '.' ||
                            $pathLower[$afterPattern] === '?') {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    // ============================================================================
    // USER-AGENT CHECKING METHODS
    // ============================================================================

    /**
     * Check if User-Agent is from known vulnerability scanner
     *
     * @param string $userAgent User-Agent header
     * @return bool True if scanner detected
     */
    public static function isScannerUserAgent(string $userAgent): bool
    {
        $userAgentLower = strtolower($userAgent);

        foreach (self::SCANNER_USER_AGENTS as $scanner) {
            if (str_contains($userAgentLower, strtolower($scanner))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if User-Agent is from legitimate bot
     *
     * NOTE: This only checks User-Agent string. For security, always perform
     * DNS verification using isLegitimateBot() method.
     *
     * @param string $userAgent User-Agent header
     * @return bool True if legitimate bot User-Agent detected
     */
    public static function isLegitimateBot(string $userAgent): bool
    {
        $userAgentLower = strtolower($userAgent);

        foreach (self::LEGITIMATE_BOTS as $bot) {
            if (str_contains($userAgentLower, strtolower($bot))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if User-Agent is fake/obsolete (impossible in 2025)
     *
     * @param string $userAgent User-Agent header
     * @return bool True if fake/obsolete browser detected
     */
    public static function isFakeUserAgent(string $userAgent): bool
    {
        if (empty($userAgent)) {
            return false; // Empty UA handled separately (100 points)
        }

        $userAgentLower = strtolower($userAgent);

        foreach (self::FAKE_USER_AGENTS as $fake) {
            if (str_contains($userAgentLower, strtolower($fake))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Classify User-Agent into threat categories
     *
     * CLASSIFICATION vs SECURITY:
     * This is CLASSIFICATION logic, not security validation.
     * - 'browser' = contains common browser keywords (permissive by design)
     * - 'mozilla' keyword matches most UAs (even bots that fingerprint browsers)
     *
     * SECURITY IMPACT:
     * - Bots wanting to appear as browsers WILL pass as 'browser'
     * - This is INTENDED (bot detection happens separately via DNS verification)
     * - Do NOT use this for security decisions, only for logging/analytics
     *
     * @param string $userAgent User-Agent header
     * @return string One of: 'scanner', 'bot', 'browser', 'unknown'
     */
    public static function classifyUserAgent(string $userAgent): string
    {
        if (empty($userAgent)) {
            return 'unknown';
        }

        // Priority 1: Known vulnerability scanners (highest threat)
        if (self::isScannerUserAgent($userAgent)) {
            return 'scanner';
        }

        // Priority 2: Legitimate bots (beneficial)
        if (self::isLegitimateBot($userAgent)) {
            return 'bot';
        }

        // Priority 3: Check if it looks like a browser
        $userAgentLower = strtolower($userAgent);
        $browserPatterns = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'mozilla'];

        foreach ($browserPatterns as $browser) {
            if (str_contains($userAgentLower, $browser)) {
                return 'browser';
            }
        }

        return 'unknown';
    }

    // ============================================================================
    // GEOGRAPHIC BLOCKING METHODS
    // ============================================================================

    /**
     * Check if country code is geo-blocked
     *
     * @param string $countryCode Two-letter ISO country code (e.g., 'RU', 'CN')
     * @return bool True if country is blocked
     */
    public static function isBlockedCountry(string $countryCode): bool
    {
        return in_array(strtoupper($countryCode), self::BLOCKED_COUNTRIES, true);
    }

    /**
     * Get list of blocked country codes
     *
     * @return array<string> Array of two-letter country codes
     */
    public static function getBlockedCountries(): array
    {
        return self::BLOCKED_COUNTRIES;
    }

    // ============================================================================
    // DNS VERIFICATION METHODS
    // ============================================================================

    /**
     * Get legitimate hostname suffixes for a bot
     *
     * @param string $botName Bot name (e.g., 'googlebot', 'bingbot')
     * @return array<string>|null Array of allowed hostname suffixes, or null if not found
     */
    public static function getLegitimateHostnameSuffixes(string $botName): ?array
    {
        $botNameLower = strtolower($botName);
        return self::LEGITIMATE_BOT_HOSTNAMES[$botNameLower] ?? null;
    }

    /**
     * Check if IP is in OpenAI IP ranges
     *
     * @param string $ip IP address to check
     * @return bool True if IP is in OpenAI ranges
     */
    public static function isOpenAIIP(string $ip): bool
    {
        foreach (self::OPENAI_IP_RANGES as $cidr) {
            if (self::ipInCIDR($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get OpenAI IP ranges
     *
     * @return array<string> Array of CIDR notation IP ranges
     */
    public static function getOpenAIIPRanges(): array
    {
        return self::OPENAI_IP_RANGES;
    }

    /**
     * Check if IP is within CIDR range
     *
     * Delegates to IPUtils for centralized CIDR matching.
     *
     * @param string $ip IP address to check
     * @param string $cidr CIDR notation (e.g., '192.168.1.0/24')
     * @return bool True if IP is in range
     */
    private static function ipInCIDR(string $ip, string $cidr): bool
    {
        return IPUtils::isInCIDR($ip, $cidr);
    }

    // ============================================================================
    // SCORING METHODS
    // ============================================================================

    /**
     * Get score for critical path detection
     *
     * @return int Score points (30)
     */
    public static function getCriticalPathScore(): int
    {
        return self::SCORE_CRITICAL_PATH;
    }

    /**
     * Get score for CMS path detection
     *
     * @return int Score points (15)
     */
    public static function getCMSPathScore(): int
    {
        return self::SCORE_CMS_PATH;
    }

    /**
     * Get score for config path detection
     *
     * @return int Score points (10)
     */
    public static function getConfigPathScore(): int
    {
        return self::SCORE_CONFIG_PATH;
    }

    /**
     * Get score for scanner User-Agent detection
     *
     * @return int Score points (30)
     */
    public static function getScannerUserAgentScore(): int
    {
        return self::SCORE_SCANNER_USER_AGENT;
    }

    /**
     * Get score for fake User-Agent detection
     *
     * @return int Score points (50)
     */
    public static function getFakeUserAgentScore(): int
    {
        return self::SCORE_FAKE_USER_AGENT;
    }

    /**
     * Get score for NULL User-Agent
     *
     * @return int Score points (100 - instant ban)
     */
    public static function getNullUserAgentScore(): int
    {
        return self::SCORE_NULL_USER_AGENT;
    }

    /**
     * Get score for geo-blocked country
     *
     * @return int Score points (50)
     */
    public static function getGeoBlockedScore(): int
    {
        return self::SCORE_GEO_BLOCKED;
    }

    /**
     * Get score for Unicode obfuscation
     *
     * @return int Score points (20)
     */
    public static function getUnicodeObfuscationScore(): int
    {
        return self::SCORE_UNICODE_OBFUSCATION;
    }


    /**
     * Get score for rate limit exceeded
     *
     * @return int Score points (20)
     */
    public static function getRateLimitScore(): int
    {
        return self::SCORE_RATE_LIMIT_EXCEEDED;
    }

    /**
     * Get ban threshold score
     *
     * @return int Threshold points (50)
     */
    public static function getScoreThreshold(): int
    {
        return self::SCORE_THRESHOLD;
    }

    /**
     * Calculate total threat score for a request
     *
     * @param string $path Request path
     * @param string $userAgent User-Agent header
     * @param string|null $countryCode Optional country code
     * @return array{score: int, reasons: array<string>} Score and reasons
     */
    public static function calculateThreatScore(
        string $path,
        string $userAgent,
        ?string $countryCode = null
    ): array {
        $score = 0;
        $reasons = [];

        // Check critical paths
        if (self::isCriticalPath($path)) {
            $score += self::SCORE_CRITICAL_PATH;
            $reasons[] = 'critical_path';
        }

        // Check CMS paths
        if (self::isCMSPath($path)) {
            $score += self::SCORE_CMS_PATH;
            $reasons[] = 'cms_scan';
        }

        // Check config paths
        if (self::isConfigPath($path)) {
            $score += self::SCORE_CONFIG_PATH;
            $reasons[] = 'config_scan';
        }

        // Check User-Agent
        if (empty($userAgent)) {
            $score += self::SCORE_NULL_USER_AGENT;
            $reasons[] = 'null_user_agent';
        } elseif (self::isScannerUserAgent($userAgent)) {
            $score += self::SCORE_SCANNER_USER_AGENT;
            $reasons[] = 'scanner_user_agent';
        } elseif (self::isFakeUserAgent($userAgent)) {
            $score += self::SCORE_FAKE_USER_AGENT;
            $reasons[] = 'fake_user_agent';
        }

        // Check geo-blocking
        if ($countryCode && self::isBlockedCountry($countryCode)) {
            $score += self::SCORE_GEO_BLOCKED;
            $reasons[] = "geo_blocked_{$countryCode}";
        }

        return [
            'score' => $score,
            'reasons' => $reasons,
        ];
    }

    /**
     * Check if score exceeds ban threshold
     *
     * @param int $score Current score
     * @return bool True if score >= threshold
     */
    public static function shouldBan(int $score): bool
    {
        return $score >= self::SCORE_THRESHOLD;
    }

    // ============================================================================
    // PATTERN STATISTICS METHODS
    // ============================================================================

    /**
     * Get total number of critical paths
     *
     * @return int Count of patterns
     */
    public static function getCriticalPathsCount(): int
    {
        return count(self::CRITICAL_PATHS);
    }

    /**
     * Get total number of CMS paths
     *
     * @return int Count of patterns
     */
    public static function getCMSPathsCount(): int
    {
        return count(self::CMS_PATHS);
    }

    /**
     * Get total number of config paths
     *
     * @return int Count of patterns
     */
    public static function getConfigPathsCount(): int
    {
        return count(self::CONFIG_PATHS);
    }

    /**
     * Get total number of scanner User-Agents
     *
     * @return int Count of patterns
     */
    public static function getScannerUserAgentsCount(): int
    {
        return count(self::SCANNER_USER_AGENTS);
    }

    /**
     * Get total number of legitimate bots
     *
     * @return int Count of patterns
     */
    public static function getLegitimateBotsCount(): int
    {
        return count(self::LEGITIMATE_BOTS);
    }

    /**
     * Get total number of fake User-Agent patterns
     *
     * @return int Count of patterns
     */
    public static function getFakeUserAgentsCount(): int
    {
        return count(self::FAKE_USER_AGENTS);
    }

    /**
     * Get comprehensive pattern statistics
     *
     * @return array<string, int> Pattern counts by category
     */
    public static function getStatistics(): array
    {
        return [
            'critical_paths' => self::getCriticalPathsCount(),
            'cms_paths' => self::getCMSPathsCount(),
            'config_paths' => self::getConfigPathsCount(),
            'scanner_user_agents' => self::getScannerUserAgentsCount(),
            'legitimate_bots' => self::getLegitimateBotsCount(),
            'fake_user_agents' => self::getFakeUserAgentsCount(),
            'blocked_countries' => count(self::BLOCKED_COUNTRIES),
            'openai_ip_ranges' => count(self::OPENAI_IP_RANGES),
            'bot_hostnames' => count(self::LEGITIMATE_BOT_HOSTNAMES),
        ];
    }
}
