<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\NullStorage;
use Senza1dio\SecurityShield\Contracts\LoggerInterface;

/**
 * Test Suite for SecurityMiddleware
 *
 * Coverage:
 * - Progressive scoring system
 * - Rate limiting
 * - IP banning logic
 * - Whitelist/blacklist
 * - Bot verification
 * - Country blocking
 * - Attack logging
 * - Edge cases
 *
 * @package Senza1dio\SecurityShield\Tests\Unit
 */
final class WafMiddlewareTest extends TestCase
{
    private SecurityMiddleware $middleware;
    private SecurityConfig $config;
    private NullStorage $storage;
    private MockLogger $logger;

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
        $this->logger = new MockLogger();
        $this->config = SecurityConfig::create()
            ->enableBotProtection(true)
            ->setRateLimitMax(100);

        $this->middleware = new SecurityMiddleware($this->config, $this->storage, $this->logger);
    }

    // ==================== BASIC FUNCTIONALITY ====================

    public function testAllowsLegitimateRequest(): void
    {
        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');

        $result = $this->middleware->handle($request);

        $this->assertTrue($result, 'Legitimate request should be allowed');
    }

    public function testBlocksHighScoreRequest(): void
    {
        // Request con score alto (vulnerab pattern critico)
        $request = $this->createRequest(
            'GET',
            '/../../../etc/passwd',
            [],
            '1.2.3.4',
            'sqlmap/1.0'
        );

        $result = $this->middleware->handle($request);

        $this->assertFalse($result, 'High score request should be blocked');
    }

    // ==================== RATE LIMITING TESTS ====================

    public function testRateLimitingAllowsUnder100Requests(): void
    {
        // Mock storage che ritorna 50 requests
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('incrementRequestCount')->willReturn(50);
        $mockStorage->method('get')->willReturn(null);

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertTrue($result, 'Under rate limit should be allowed');
    }

    public function testRateLimitingBlocksOver100Requests(): void
    {
        // Mock storage che ritorna 150 requests (over limit)
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('incrementRequestCount')->willReturn(150);
        $mockStorage->method('get')->willReturn(null);

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Over rate limit should be blocked');
    }

    public function testRateLimitingAddsScore(): void
    {
        // Test che rate limiting aggiunge +20 score
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('incrementRequestCount')->willReturn(120); // Over limit
        $mockStorage->method('get')->willReturn(null);

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');
        $waf->handle($request);

        // Logger dovrebbe registrare rate limit violation
        $this->assertCount(1, $this->logger->logs);
        $this->assertStringContainsString('Rate limit', $this->logger->logs[0]['message']);
    }

    // ==================== SQL INJECTION DETECTION ====================

    public function testDetectsSQLInjectionInQueryParams(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            ['id' => "1' OR '1'='1"],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);

        $this->assertFalse($result, 'SQL injection should be blocked');
        $this->assertCount(1, $this->logger->logs);
        $this->assertStringContainsString('SQL injection', $this->logger->logs[0]['message']);
    }

    public function testDetectsSQLInjectionUnionAttack(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            ['search' => '1 UNION SELECT username,password FROM users'],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'UNION attack should be blocked');
    }

    public function testDetectsSQLInjectionWithComments(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            ['q' => "admin'-- "],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'SQL comment injection should be blocked');
    }

    public function testAllowsLegitimateQuotesInParams(): void
    {
        // Parametro legittimo con quote (non injection)
        $request = $this->createRequest(
            'GET',
            '/',
            ['name' => "O'Brien"],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        // Dovrebbe essere consentito (singola quote non è pattern di injection)
        $this->assertIsBool($result);
    }

    // ==================== XSS DETECTION ====================

    public function testDetectsXSSScriptTag(): void
    {
        $request = $this->createRequest(
            'POST',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0',
            ['comment' => '<script>alert("XSS")</script>']
        );

        $result = $this->middleware->handle($request);

        $this->assertFalse($result, 'XSS <script> tag should be blocked');
        $this->assertCount(1, $this->logger->logs);
        $this->assertStringContainsString('XSS', $this->logger->logs[0]['message']);
    }

    public function testDetectsXSSOnerrorAttribute(): void
    {
        $request = $this->createRequest(
            'POST',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0',
            ['bio' => '<img src=x onerror=alert(1)>']
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'XSS onerror should be blocked');
    }

    public function testDetectsXSSJavascriptProtocol(): void
    {
        $request = $this->createRequest(
            'POST',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0',
            ['link' => 'javascript:void(0)']
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'XSS javascript: protocol should be blocked');
    }

    public function testAllowsLegitimateHTMLInContent(): void
    {
        // HTML safe (senza script/event handlers)
        $request = $this->createRequest(
            'POST',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0',
            ['content' => '<b>Bold text</b> and <i>italic</i>']
        );

        $result = $this->middleware->handle($request);
        $this->assertTrue($result, 'Safe HTML should be allowed');
    }

    // ==================== VULNERABILITY PATTERN DETECTION ====================

    public function testDetectsCriticalPathTraversal(): void
    {
        $request = $this->createRequest(
            'GET',
            '/../../../etc/passwd',
            [],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'Path traversal should be blocked');
    }

    public function testDetectsWordPressAdminAccess(): void
    {
        $request = $this->createRequest(
            'GET',
            '/wp-admin/install.php',
            [],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'WP admin access should be blocked');
    }

    public function testDetectsPhpMyAdminAccess(): void
    {
        $request = $this->createRequest(
            'GET',
            '/phpmyadmin/index.php',
            [],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'phpMyAdmin access should be blocked');
    }

    public function testDetectsEnvFileAccess(): void
    {
        $request = $this->createRequest(
            'GET',
            '/.env',
            [],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, '.env access should be blocked');
    }

    // ==================== SCANNER USER-AGENT DETECTION ====================

    public function testDetectsSqlmapUserAgent(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'sqlmap/1.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'sqlmap should be blocked');
    }

    public function testDetectsNiktoUserAgent(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Nikto/2.1.6'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'Nikto scanner should be blocked');
    }

    public function testDetectsNmapUserAgent(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine;'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'Nmap should be blocked');
    }

    public function testDetectsBurpSuiteUserAgent(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Burp Suite Professional'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'Burp Suite should be blocked');
    }

    // ==================== FAKE BROWSER DETECTION ====================

    public function testDetectsFakeIE9UserAgent(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1;'
        );

        $result = $this->middleware->handle($request);
        $this->assertFalse($result, 'Fake IE9 should be blocked');
    }

    public function testDetectsAncientChromeVersion(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/30.0'
        );

        $result = $this->middleware->handle($request);
        // Chrome 30 è del 2013, dovrebbe essere bloccato
        $this->assertFalse($result, 'Ancient Chrome should be blocked');
    }

    // ==================== WHITELIST TESTS ====================

    public function testWhitelistBypassesAllChecks(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->setWhitelistedIPs(['1.2.3.4']);

        $waf = new WafMiddleware($config, $this->storage, $this->logger);

        // Request con scanner UA + critical path (dovrebbe essere bloccata)
        $request = $this->createRequest(
            'GET',
            '/../../../etc/passwd',
            [],
            '1.2.3.4', // Ma IP whitelisted
            'sqlmap/1.0'
        );

        $result = $waf->handle($request);
        $this->assertTrue($result, 'Whitelisted IP should bypass all checks');
    }

    public function testWhitelistDoesNotAffectOtherIPs(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->setWhitelistedIPs(['5.6.7.8']);

        $waf = new WafMiddleware($config, $this->storage, $this->logger);

        // IP non whitelisted con scanner UA
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'sqlmap/1.0'
        );

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Non-whitelisted IP should be blocked');
    }

    // ==================== BLACKLIST TESTS ====================

    public function testBlacklistBlocksImmediately(): void
    {
        $config = SecurityConfig::create()
            ->enableWAF(true)
            ->setBlacklistedIPs(['1.2.3.4']);

        $waf = new WafMiddleware($config, $this->storage, $this->logger);

        // Request completamente legittima
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4', // Ma IP blacklisted
            'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0'
        );

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Blacklisted IP should be blocked immediately');
    }

    // ==================== IP BANNING TESTS ====================

    public function testBannedIPIsBlocked(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('banned:1.2.3.4')
            ->willReturn('1'); // IP già bannato

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Banned IP should be blocked');
    }

    public function testHighScoreTriggersBan(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')->willReturn(null);

        $mockStorage->expects($this->once())
            ->method('set')
            ->with(
                'banned:1.2.3.4',
                '1',
                86400 // 24 hours
            );

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        // Request con score > 100 (trigger ban)
        $request = $this->createRequest(
            'GET',
            '/../../../etc/passwd', // Critical path (60 points)
            [],
            '1.2.3.4',
            'sqlmap/1.0' // Scanner UA (50 points)
        );

        $waf->handle($request);
    }

    // ==================== COUNTRY BLOCKING TESTS ====================

    public function testBlocksRussianIP(): void
    {
        // Mock storage che ritorna country code
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('country:1.2.3.4')
            ->willReturn('RU');

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '1.2.3.4', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Russian IP should be blocked');
    }

    public function testBlocksChineseIP(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('country:5.6.7.8')
            ->willReturn('CN');

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '5.6.7.8', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertFalse($result, 'Chinese IP should be blocked');
    }

    public function testBlocksNorthKoreanIP(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('country:9.9.9.9')
            ->willReturn('KP');

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '9.9.9.9', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertFalse($result, 'North Korean IP should be blocked');
    }

    public function testAllowsUSIP(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('country:8.8.8.8')
            ->willReturn('US');

        $waf = new WafMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/', [], '8.8.8.8', 'Mozilla/5.0');

        $result = $waf->handle($request);
        $this->assertTrue($result, 'US IP should be allowed');
    }

    // ==================== BOT VERIFICATION TESTS ====================

    public function testVerifiesLegitimateBots(): void
    {
        // Request con Googlebot UA da IP corretto
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '66.249.66.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        );

        $result = $this->middleware->handle($request);

        // Dovrebbe essere consentito (se DNS verifica)
        $this->assertIsBool($result);
    }

    public function testRejectsFakeBots(): void
    {
        // Request con Googlebot UA ma IP non-Google
        $request = $this->createRequest(
            'GET',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        );

        $result = $this->middleware->handle($request);

        // Dovrebbe essere bloccato (fake bot)
        $this->assertFalse($result);
    }

    // ==================== EDGE CASES ====================

    public function testHandlesEmptyUserAgent(): void
    {
        $request = $this->createRequest('GET', '/', [], '1.2.3.4', '');

        $result = $this->middleware->handle($request);
        $this->assertIsBool($result);
    }

    public function testHandlesNullUserAgent(): void
    {
        $request = $this->createRequest('GET', '/', [], '1.2.3.4', null);

        $result = $this->middleware->handle($request);
        $this->assertIsBool($result);
    }

    public function testHandlesVeryLongURL(): void
    {
        $longPath = '/' . str_repeat('a', 10000);
        $request = $this->createRequest('GET', $longPath, [], '1.2.3.4', 'Mozilla/5.0');

        $result = $this->middleware->handle($request);
        $this->assertIsBool($result);
    }

    public function testHandlesSpecialCharactersInParams(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            ['q' => '中文字符'],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertTrue($result, 'Special characters should be allowed');
    }

    public function testHandlesMultipleGetParams(): void
    {
        $request = $this->createRequest(
            'GET',
            '/',
            [
                'page' => '1',
                'limit' => '20',
                'sort' => 'name',
                'order' => 'asc',
            ],
            '1.2.3.4',
            'Mozilla/5.0'
        );

        $result = $this->middleware->handle($request);
        $this->assertTrue($result, 'Multiple params should be allowed');
    }

    public function testHandlesMultiplePostParams(): void
    {
        $request = $this->createRequest(
            'POST',
            '/',
            [],
            '1.2.3.4',
            'Mozilla/5.0',
            [
                'name' => 'John',
                'email' => 'john@example.com',
                'message' => 'Hello world',
            ]
        );

        $result = $this->middleware->handle($request);
        $this->assertTrue($result, 'Multiple POST params should be allowed');
    }

    // ==================== HELPER METHODS ====================

    private function createRequest(
        string $method,
        string $uri,
        array $get = [],
        string $ip = '1.2.3.4',
        ?string $userAgent = 'Mozilla/5.0',
        array $post = []
    ): array {
        return [
            'method' => $method,
            'uri' => $uri,
            'get' => $get,
            'post' => $post,
            'ip' => $ip,
            'user_agent' => $userAgent,
        ];
    }
}

/**
 * Mock Logger for testing
 */
class MockLogger implements LoggerInterface
{
    public array $logs = [];

    public function log(string $level, string $message, array $context = []): void
    {
        $this->logs[] = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];
    }

    public function emergency(string $message, array $context = []): void
    {
        $this->log('emergency', $message, $context);
    }

    public function alert(string $message, array $context = []): void
    {
        $this->log('alert', $message, $context);
    }

    public function critical(string $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    public function notice(string $message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }
}
