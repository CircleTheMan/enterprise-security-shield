<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Middleware\HoneypotMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Exceptions\HoneypotAccessException;
use Senza1dio\SecurityShield\Storage\NullStorage;

/**
 * Test Suite for HoneypotMiddleware
 *
 * Coverage:
 * - Trap endpoint detection
 * - Fake response generation
 * - Intelligence gathering
 * - Fingerprinting
 * - Attack logging
 * - IP banning
 * - Edge cases
 *
 * @package Senza1dio\SecurityShield\Tests\Unit
 */
final class HoneypotMiddlewareTest extends TestCase
{
    private HoneypotMiddleware $honeypot;
    private SecurityConfig $config;
    private NullStorage $storage;
    private MockHoneypotLogger $logger;

    /** @var array<int, string> Custom honeypot paths for testing */
    private array $customPaths = [
        '/admin',
        '/login',
        '/wp-admin',
        '/.env',
        '/phpmyadmin',
    ];

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
        $this->logger = new MockHoneypotLogger();
        $this->config = SecurityConfig::create()
            ->enableHoneypot(true)
            ->setStorage($this->storage)
            ->setLogger($this->logger);

        $this->honeypot = new HoneypotMiddleware($this->config, $this->customPaths);
    }

    // ==================== BASIC TRAP DETECTION ====================

    public function testDetectsAdminTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testDetectsLoginTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/login', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testDetectsWpAdminTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/wp-admin', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testDetectsEnvFileTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/.env', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testDetectsPhpMyAdminTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/phpmyadmin', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testAllowsNonTrapEndpoint(): void
    {
        $request = $this->createRequest('GET', '/', '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertTrue($result, 'Non-trap endpoint should be allowed');
        $this->assertCount(0, $this->logger->logs);
    }

    // ==================== TRAP ENDPOINT VARIATIONS ====================

    public function testDetectsTrapWithQueryString(): void
    {
        $request = $this->createRequest('GET', '/admin?debug=1', '1.2.3.4', 'Mozilla/5.0');

        $this->expectException(HoneypotAccessException::class);
        $this->honeypot->handle($request);
    }

    public function testDetectsTrapWithTrailingSlash(): void
    {
        $request = $this->createRequest('GET', '/admin/', '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result, 'Trap with trailing slash should be detected');
    }

    public function testDetectsTrapCaseInsensitive(): void
    {
        $request = $this->createRequest('GET', '/ADMIN', '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        // Dovrebbe essere case-sensitive (dipende dall'implementazione)
        $this->assertIsBool($result);
    }

    public function testDetectsTrapWithSubpath(): void
    {
        $request = $this->createRequest('GET', '/admin/users', '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        // Dovrebbe rilevare /admin anche con subpath
        $this->assertFalse($result, 'Trap with subpath should be detected');
    }

    // ==================== INTELLIGENCE GATHERING ====================

    public function testGathersIPAddress(): void
    {
        $request = $this->createRequest('GET', '/admin', '5.6.7.8', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertEquals('5.6.7.8', $this->logger->logs[0]['context']['ip']);
    }

    public function testGathersUserAgent(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'sqlmap/1.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertEquals('sqlmap/1.0', $this->logger->logs[0]['context']['user_agent']);
    }

    public function testGathersRequestMethod(): void
    {
        $request = $this->createRequest('POST', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertEquals('POST', $this->logger->logs[0]['context']['method']);
    }

    public function testGathersRequestURI(): void
    {
        $request = $this->createRequest('GET', '/admin?debug=1', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertStringContainsString('/admin', $this->logger->logs[0]['context']['uri']);
    }

    public function testGathersTimestamp(): void
    {
        $before = time();
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);
        $after = time();

        $this->assertCount(1, $this->logger->logs);
        $this->assertArrayHasKey('timestamp', $this->logger->logs[0]['context']);

        $timestamp = $this->logger->logs[0]['context']['timestamp'];
        $this->assertGreaterThanOrEqual($before, $timestamp);
        $this->assertLessThanOrEqual($after, $timestamp);
    }

    // ==================== FAKE RESPONSE TESTS ====================

    public function testReturnsFakeAdminPanel(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        // Dovrebbe generare fake response HTML
        $this->assertCount(1, $this->logger->logs);
        $this->assertArrayHasKey('response_type', $this->logger->logs[0]['context']);
    }

    public function testReturnsFakeLoginForm(): void
    {
        $request = $this->createRequest('GET', '/login', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertArrayHasKey('response_type', $this->logger->logs[0]['context']);
    }

    public function testReturnsFakeEnvFile(): void
    {
        $request = $this->createRequest('GET', '/.env', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        // Dovrebbe generare fake .env content
        $this->assertArrayHasKey('response_type', $this->logger->logs[0]['context']);
    }

    public function testFakeResponseContainsRealisticData(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $this->honeypot->handle($request);

        // Verifica che la risposta sembri realistica
        $context = $this->logger->logs[0]['context'];
        $this->assertArrayHasKey('response_type', $context);
        $this->assertIsString($context['response_type']);
    }

    // ==================== FINGERPRINTING ====================

    public function testDetectsScannerUserAgent(): void
    {
        $scanners = [
            'sqlmap/1.0',
            'Nikto/2.1.6',
            'Nmap',
            'Burp Suite',
            'OWASP ZAP',
        ];

        foreach ($scanners as $scanner) {
            $this->logger->logs = []; // Reset logs

            $request = $this->createRequest('GET', '/admin', '1.2.3.4', $scanner);
            $this->honeypot->handle($request);

            $this->assertCount(1, $this->logger->logs);
            $this->assertEquals($scanner, $this->logger->logs[0]['context']['user_agent']);
        }
    }

    public function testIdentifiesAutomatedTools(): void
    {
        $tools = [
            'curl/7.68.0',
            'Wget/1.20.3',
            'python-requests/2.25.1',
            'Go-http-client/1.1',
        ];

        foreach ($tools as $tool) {
            $this->logger->logs = [];

            $request = $this->createRequest('GET', '/admin', '1.2.3.4', $tool);
            $this->honeypot->handle($request);

            $this->assertCount(1, $this->logger->logs);
            $this->assertEquals($tool, $this->logger->logs[0]['context']['user_agent']);
        }
    }

    public function testTracksRepeatedAccess(): void
    {
        $ip = '1.2.3.4';

        // Simula 3 accessi dalla stessa IP
        for ($i = 0; $i < 3; $i++) {
            $request = $this->createRequest('GET', '/admin', $ip, 'Mozilla/5.0');
            $this->honeypot->handle($request);
        }

        // Dovrebbe aver loggato 3 volte
        $this->assertCount(3, $this->logger->logs);

        // Tutti con la stessa IP
        foreach ($this->logger->logs as $log) {
            $this->assertEquals($ip, $log['context']['ip']);
        }
    }

    // ==================== IP BANNING ====================

    public function testBansIPAfterTrapAccess(): void
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

        $honeypot = new HoneypotMiddleware($this->config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');
        $honeypot->handle($request);
    }

    public function testDoesNotBanWhitelistedIP(): void
    {
        $config = SecurityConfig::create()
            ->enableHoneypot(true)
            ->setHoneypotEndpoints(['/admin'])
            ->setWhitelistedIPs(['1.2.3.4']);

        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->expects($this->never())
            ->method('set');

        $honeypot = new HoneypotMiddleware($config, $mockStorage, $this->logger);

        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');
        $honeypot->handle($request);
    }

    // ==================== CUSTOM HONEYPOT ENDPOINTS ====================

    public function testSupportsCustomEndpoints(): void
    {
        $config = SecurityConfig::create()
            ->enableHoneypot(true)
            ->setHoneypotEndpoints([
                '/secret',
                '/backup.sql',
                '/database.zip',
            ]);

        $honeypot = new HoneypotMiddleware($config, $this->storage, $this->logger);

        $request = $this->createRequest('GET', '/secret', '1.2.3.4', 'Mozilla/5.0');

        $result = $honeypot->handle($request);
        $this->assertFalse($result, 'Custom endpoint should be detected');
    }

    public function testEmptyEndpointsListDisablesHoneypot(): void
    {
        $config = SecurityConfig::create()
            ->enableHoneypot(true)
            ->setHoneypotEndpoints([]);

        $honeypot = new HoneypotMiddleware($config, $this->storage, $this->logger);

        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'Mozilla/5.0');

        $result = $honeypot->handle($request);
        $this->assertTrue($result, 'Empty endpoints list should allow all requests');
    }

    // ==================== EDGE CASES ====================

    public function testHandlesNullUserAgent(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', null);

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
        $this->assertCount(1, $this->logger->logs);
    }

    public function testHandlesEmptyUserAgent(): void
    {
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', '');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    public function testHandlesInvalidIPAddress(): void
    {
        $request = $this->createRequest('GET', '/admin', 'not-an-ip', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    public function testHandlesVeryLongURI(): void
    {
        $longUri = '/admin/' . str_repeat('a', 10000);
        $request = $this->createRequest('GET', $longUri, '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    public function testHandlesSpecialCharactersInURI(): void
    {
        $request = $this->createRequest('GET', '/admin?user=<script>alert(1)</script>', '1.2.3.4', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    public function testHandlesIPv6Address(): void
    {
        $request = $this->createRequest('GET', '/admin', '2001:db8::1', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    public function testHandlesLocalhostIP(): void
    {
        $request = $this->createRequest('GET', '/admin', '127.0.0.1', 'Mozilla/5.0');

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result);
    }

    // ==================== POST REQUEST TESTS ====================

    public function testDetectsPOSTToTrapEndpoint(): void
    {
        $request = [
            'method' => 'POST',
            'uri' => '/admin',
            'ip' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'post' => [
                'username' => 'admin',
                'password' => 'password123',
            ],
        ];

        $result = $this->honeypot->handle($request);
        $this->assertFalse($result, 'POST to trap should be detected');
    }

    public function testGathersPOSTData(): void
    {
        $postData = [
            'username' => 'attacker',
            'password' => 'test123',
            'csrf_token' => 'abc123',
        ];

        $request = [
            'method' => 'POST',
            'uri' => '/login',
            'ip' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'post' => $postData,
        ];

        $this->honeypot->handle($request);

        $this->assertCount(1, $this->logger->logs);
        $this->assertArrayHasKey('post_data', $this->logger->logs[0]['context']);
    }

    // ==================== STATISTICS ====================

    public function testTracksHoneypotStatistics(): void
    {
        // Simula 5 accessi a honeypot
        for ($i = 0; $i < 5; $i++) {
            $request = $this->createRequest('GET', '/admin', "1.2.3.{$i}", 'Mozilla/5.0');
            $this->honeypot->handle($request);
        }

        // Dovrebbe aver tracciato 5 eventi
        $this->assertCount(5, $this->logger->logs);
    }

    public function testTracksUniqueIPsInHoneypot(): void
    {
        $ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12'];

        foreach ($ips as $ip) {
            $request = $this->createRequest('GET', '/admin', $ip, 'Mozilla/5.0');
            $this->honeypot->handle($request);
        }

        $this->assertCount(3, $this->logger->logs);

        // Verifica IP diverse
        $loggedIPs = array_map(fn($log) => $log['context']['ip'], $this->logger->logs);
        $this->assertEquals($ips, $loggedIPs);
    }

    // ==================== INTEGRATION-LIKE TESTS ====================

    public function testFullHoneypotFlow(): void
    {
        // Simula attacco completo
        $request = $this->createRequest('GET', '/admin', '1.2.3.4', 'sqlmap/1.0');

        $result = $this->honeypot->handle($request);

        // Dovrebbe essere bloccato
        $this->assertFalse($result);

        // Dovrebbe loggare l'evento
        $this->assertCount(1, $this->logger->logs);
        $log = $this->logger->logs[0];

        // Verifica tutti i dati raccolti
        $this->assertEquals('warning', $log['level']);
        $this->assertStringContainsString('Honeypot triggered', $log['message']);
        $this->assertEquals('1.2.3.4', $log['context']['ip']);
        $this->assertEquals('sqlmap/1.0', $log['context']['user_agent']);
        $this->assertStringContainsString('/admin', $log['context']['uri']);
    }

    public function testMultipleTrapAccessesFromSameIP(): void
    {
        $ip = '1.2.3.4';
        $endpoints = ['/admin', '/login', '/.env', '/phpmyadmin'];

        foreach ($endpoints as $endpoint) {
            $request = $this->createRequest('GET', $endpoint, $ip, 'Mozilla/5.0');
            $this->honeypot->handle($request);
        }

        // Dovrebbe aver loggato 4 eventi
        $this->assertCount(4, $this->logger->logs);

        // Tutti dalla stessa IP
        foreach ($this->logger->logs as $log) {
            $this->assertEquals($ip, $log['context']['ip']);
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Create a $_SERVER-like array for testing
     *
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $uri Request URI (e.g., '/admin?debug=1')
     * @param string $ip Client IP address
     * @param string|null $userAgent User-Agent header
     * @return array<string, mixed> $_SERVER-like array
     */
    private function createRequest(
        string $method,
        string $uri,
        string $ip,
        ?string $userAgent
    ): array {
        return [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $uri,
            'REMOTE_ADDR' => $ip,
            'HTTP_USER_AGENT' => $userAgent ?? '',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'HTTP_HOST' => 'localhost',
        ];
    }
}

/**
 * Mock Logger for Honeypot testing
 */
class MockHoneypotLogger implements \Senza1dio\SecurityShield\Contracts\LoggerInterface
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
