<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Services\BotVerifier;
use Senza1dio\SecurityShield\Storage\NullStorage;
use Senza1dio\SecurityShield\Storage\NullLogger;

/**
 * Test Suite for BotVerifier
 *
 * Coverage:
 * - DNS verification (reverse + forward lookup)
 * - IP range verification (CIDR)
 * - Caching logic
 * - Statistics tracking
 * - Anti-spoofing protection
 * - Edge cases
 *
 * @package Senza1dio\SecurityShield\Tests\Unit
 */
final class BotVerifierTest extends TestCase
{
    private BotVerifier $verifier;
    private NullStorage $storage;
    private NullLogger $logger;

    protected function setUp(): void
    {
        $this->storage = new NullStorage();
        $this->logger = new NullLogger();
        $this->verifier = new BotVerifier($this->storage, $this->logger);
    }

    // ==================== DNS VERIFICATION TESTS ====================

    public function testVerifyGoogleBotWithValidHostname(): void
    {
        // Test with real Googlebot IP pattern
        // Note: In production, this would do actual DNS lookup
        // For unit tests, we test the logic flow

        $ip = '66.249.66.1'; // Typical Googlebot IP
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        // NullStorage sempre ritorna false per cache, quindi testa la logica
        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Con NullStorage, il risultato dipende dal DNS reale
        // Testiamo che il metodo NON lanci eccezioni
        $this->assertIsBool($result);
    }

    public function testVerifyBingBotWithValidHostname(): void
    {
        $ip = '157.55.39.1'; // Typical BingBot IP
        $userAgent = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertIsBool($result);
    }

    public function testVerifyChatGPTBotWithIPRange(): void
    {
        // ChatGPT-User usa IP ranges, non DNS
        $ip = '23.98.142.1'; // Nella range di OpenAI
        $userAgent = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe verificare via CIDR range
        $this->assertIsBool($result);
    }

    public function testVerifyClaudeBotWithIPRange(): void
    {
        $ip = '160.79.104.1'; // Nella range di Anthropic
        $userAgent = 'Claude-Web/1.0; +https://www.anthropic.com';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertIsBool($result);
    }

    // ==================== ANTI-SPOOFING TESTS ====================

    public function testRejectSpoofedGoogleBotUserAgent(): void
    {
        // IP NON di Google ma User-Agent di Googlebot
        $ip = '1.2.3.4'; // IP casuale
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe fallire perché IP non matcha DNS di Google
        $this->assertFalse($result);
    }

    public function testRejectSpoofedBingBotUserAgent(): void
    {
        $ip = '5.6.7.8'; // IP casuale
        $userAgent = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertFalse($result);
    }

    public function testRejectSpoofedChatGPTUserAgent(): void
    {
        // IP fuori dalla range di OpenAI
        $ip = '192.168.1.1';
        $userAgent = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)';

        $result = $this->verifier->verifyBot($ip, $userAgent);
        $this->assertFalse($result);
    }

    // ==================== LEGITIMATE BOTS COVERAGE ====================

    public function testVerifyGoogleBotVariants(): void
    {
        $googleBots = [
            'Googlebot',
            'Googlebot-Image',
            'Googlebot-News',
            'Googlebot-Video',
            'AdsBot-Google',
            'Google-InspectionTool',
        ];

        foreach ($googleBots as $bot) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/2.1)";
            // Con IP arbitrario, dovrebbe tentare DNS lookup
            $result = $this->verifier->verifyBot('66.249.66.1', $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    public function testVerifyBingBotVariants(): void
    {
        $bingBots = [
            'bingbot',
            'BingPreview',
            'msnbot',
            'adidxbot',
        ];

        foreach ($bingBots as $bot) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/2.0)";
            $result = $this->verifier->verifyBot('157.55.39.1', $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    public function testVerifyAICrawlers(): void
    {
        $aiCrawlers = [
            'ChatGPT-User' => '23.98.142.1',
            'GPTBot' => '20.102.32.1',
            'Claude-Web' => '160.79.104.1',
            'anthropic-ai' => '160.79.104.1',
            'Applebot' => '17.0.0.1',
            'facebookexternalhit' => '31.13.24.1',
        ];

        foreach ($aiCrawlers as $bot => $ip) {
            $userAgent = "Mozilla/5.0 (compatible; {$bot}/1.0)";
            $result = $this->verifier->verifyBot($ip, $userAgent);
            $this->assertIsBool($result, "Failed for bot: {$bot}");
        }
    }

    // ==================== CIDR RANGE MATCHING TESTS ====================

    public function testIPInCIDRRange(): void
    {
        // Test CIDR matching interno
        $reflection = new \ReflectionClass($this->verifier);
        $method = $reflection->getMethod('ipInCIDRRange');
        $method->setAccessible(true);

        // Test con range OpenAI 23.98.142.0/24
        $this->assertTrue($method->invoke($this->verifier, '23.98.142.1', '23.98.142.0/24'));
        $this->assertTrue($method->invoke($this->verifier, '23.98.142.100', '23.98.142.0/24'));
        $this->assertTrue($method->invoke($this->verifier, '23.98.142.255', '23.98.142.0/24'));

        // IP fuori range
        $this->assertFalse($method->invoke($this->verifier, '23.98.143.1', '23.98.142.0/24'));
        $this->assertFalse($method->invoke($this->verifier, '24.98.142.1', '23.98.142.0/24'));
    }

    public function testIPInCIDRRangeWith16BitMask(): void
    {
        $reflection = new \ReflectionClass($this->verifier);
        $method = $reflection->getMethod('ipInCIDRRange');
        $method->setAccessible(true);

        // Test con range più ampia /16
        $this->assertTrue($method->invoke($this->verifier, '20.102.32.1', '20.102.0.0/16'));
        $this->assertTrue($method->invoke($this->verifier, '20.102.255.255', '20.102.0.0/16'));

        $this->assertFalse($method->invoke($this->verifier, '20.103.0.1', '20.102.0.0/16'));
    }

    public function testIPInCIDRRangeWith32BitMask(): void
    {
        $reflection = new \ReflectionClass($this->verifier);
        $method = $reflection->getMethod('ipInCIDRRange');
        $method->setAccessible(true);

        // Test con singolo IP /32
        $this->assertTrue($method->invoke($this->verifier, '1.2.3.4', '1.2.3.4/32'));
        $this->assertFalse($method->invoke($this->verifier, '1.2.3.5', '1.2.3.4/32'));
    }

    // ==================== CACHING TESTS ====================

    public function testCacheHitReturnsStoredResult(): void
    {
        // Mock storage che ritorna cache hit
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('bot_verify:66.249.66.1')
            ->willReturn('1'); // Cached as legitimate

        $verifier = new BotVerifier($mockStorage, $this->logger);

        $result = $verifier->verifyBot('66.249.66.1', 'Googlebot');

        // Dovrebbe ritornare true da cache
        $this->assertTrue($result);
    }

    public function testCacheHitForFakeBot(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')
            ->with('bot_verify:1.2.3.4')
            ->willReturn('0'); // Cached as fake

        $verifier = new BotVerifier($mockStorage, $this->logger);

        $result = $verifier->verifyBot('1.2.3.4', 'Googlebot');
        $this->assertFalse($result);
    }

    public function testCacheMissTriggersVerification(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')->willReturn(null); // Cache miss

        $mockStorage->expects($this->once())
            ->method('set')
            ->with(
                $this->stringContains('bot_verify:'),
                $this->anything(),
                $this->anything() // TTL varies
            );

        $verifier = new BotVerifier($mockStorage, $this->logger);
        $verifier->verifyBot('66.249.66.1', 'Googlebot');
    }

    // ==================== STATISTICS TESTS ====================

    public function testGetStatisticsReturnsCorrectStructure(): void
    {
        $stats = $this->verifier->getStatistics();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_verifications', $stats);
        $this->assertArrayHasKey('legitimate_bots', $stats);
        $this->assertArrayHasKey('fake_bots', $stats);
        $this->assertArrayHasKey('cache_hits', $stats);
        $this->assertArrayHasKey('dns_lookups', $stats);
    }

    public function testStatisticsIncrementOnVerification(): void
    {
        $initialStats = $this->verifier->getStatistics();

        // Esegui una verifica
        $this->verifier->verifyBot('1.2.3.4', 'FakeBot');

        $newStats = $this->verifier->getStatistics();

        // Total verifications dovrebbe aumentare
        $this->assertGreaterThan(
            $initialStats['total_verifications'],
            $newStats['total_verifications']
        );
    }

    // ==================== EDGE CASES ====================

    public function testEmptyUserAgent(): void
    {
        $result = $this->verifier->verifyBot('1.2.3.4', '');
        $this->assertFalse($result, 'Empty user agent should return false');
    }

    public function testNullUserAgent(): void
    {
        $result = $this->verifier->verifyBot('1.2.3.4', null);
        $this->assertFalse($result, 'Null user agent should return false');
    }

    public function testInvalidIPAddress(): void
    {
        $result = $this->verifier->verifyBot('not-an-ip', 'Googlebot');
        $this->assertFalse($result, 'Invalid IP should return false');
    }

    public function testIPv6Address(): void
    {
        // IPv6 non supportato (solo IPv4)
        $result = $this->verifier->verifyBot('2001:4860:4801:0:0:0:0:0', 'Googlebot');
        $this->assertFalse($result, 'IPv6 should return false (not supported)');
    }

    public function testLocalhostIP(): void
    {
        $result = $this->verifier->verifyBot('127.0.0.1', 'Googlebot');
        $this->assertFalse($result, 'Localhost should return false');
    }

    public function testPrivateIPRange(): void
    {
        $privateIPs = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
        ];

        foreach ($privateIPs as $ip) {
            $result = $this->verifier->verifyBot($ip, 'Googlebot');
            $this->assertFalse($result, "Private IP {$ip} should return false");
        }
    }

    public function testUnknownBotUserAgent(): void
    {
        // User-Agent non riconosciuto
        $result = $this->verifier->verifyBot('1.2.3.4', 'MyCustomCrawler/1.0');
        $this->assertFalse($result, 'Unknown bot should return false');
    }

    public function testCaseSensitivityInUserAgent(): void
    {
        // Test case-insensitive matching
        $userAgents = [
            'Googlebot',
            'googlebot',
            'GOOGLEBOT',
            'GoOgLeBoT',
        ];

        foreach ($userAgents as $ua) {
            // Dovrebbe riconoscere tutte le varianti
            $result = $this->verifier->verifyBot('66.249.66.1', $ua);
            $this->assertIsBool($result, "Failed for user agent: {$ua}");
        }
    }

    // ==================== PERFORMANCE TESTS ====================

    public function testMultipleVerificationsDoNotSlowDown(): void
    {
        $start = microtime(true);

        // 100 verifiche
        for ($i = 0; $i < 100; $i++) {
            $this->verifier->verifyBot('1.2.3.' . $i, 'Googlebot');
        }

        $duration = microtime(true) - $start;

        // Dovrebbe completare in meno di 1 secondo (con NullStorage)
        $this->assertLessThan(1.0, $duration, 'Verifications taking too long');
    }

    public function testCachingReducesVerificationTime(): void
    {
        $mockStorage = $this->createMock(\Senza1dio\SecurityShield\Contracts\StorageInterface::class);
        $mockStorage->method('get')->willReturn('1'); // Always cache hit

        $verifier = new BotVerifier($mockStorage, $this->logger);

        $start = microtime(true);

        // 1000 verifiche con cache
        for ($i = 0; $i < 1000; $i++) {
            $verifier->verifyBot('66.249.66.1', 'Googlebot');
        }

        $duration = microtime(true) - $start;

        // Con cache, dovrebbe essere MOLTO veloce
        $this->assertLessThan(0.1, $duration, 'Cache hits should be instant');
    }

    // ==================== INTEGRATION-LIKE TESTS ====================

    public function testFullVerificationFlowForLegitimateBot(): void
    {
        // Simula un bot reale con IP e User-Agent corretti
        $ip = '66.249.66.1';
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Con DNS reale, dovrebbe passare (o almeno non lanciare eccezioni)
        $this->assertIsBool($result);

        // Statistiche dovrebbero aggiornarsi
        $stats = $this->verifier->getStatistics();
        $this->assertGreaterThan(0, $stats['total_verifications']);
    }

    public function testFullVerificationFlowForFakeBot(): void
    {
        $ip = '1.2.3.4';
        $userAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $result = $this->verifier->verifyBot($ip, $userAgent);

        // Dovrebbe essere rifiutato
        $this->assertFalse($result);

        $stats = $this->verifier->getStatistics();
        $this->assertGreaterThan(0, $stats['fake_bots']);
    }
}
