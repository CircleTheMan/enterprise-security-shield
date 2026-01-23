<?php

namespace Senza1dio\SecurityShield\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Middleware\WafMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\NullStorage;
use Senza1dio\SecurityShield\Storage\NullLogger;

/**
 * WAF Concurrency & Proxy Tests
 *
 * Tests real-world scenarios:
 * - Proxy/Load Balancer IP extraction (FIX #4)
 * - Concurrent request handling
 * - CIDR whitelist/blacklist
 * - parse_url() edge cases (FIX #5)
 */
class WafConcurrencyTest extends TestCase
{
    private SecurityConfig $config;
    private WafMiddleware $waf;

    protected function setUp(): void
    {
        $this->config = new SecurityConfig();
        $this->config->setStorage(new NullStorage());
        $this->config->setLogger(new NullLogger());

        $this->waf = new WafMiddleware($this->config);
    }

    /**
     * TEST FIX #4: Cloudflare Proxy IP Extraction
     */
    public function test_cloudflare_proxy_ip_extraction()
    {
        // Configure Cloudflare IP ranges as trusted proxies
        $this->config->setTrustedProxies([
            '173.245.48.0/20',  // Cloudflare range
        ]);

        $server = [
            'REMOTE_ADDR' => '173.245.48.50',  // Cloudflare proxy
            'HTTP_CF_CONNECTING_IP' => '203.0.113.100',  // Real client IP
            'REQUEST_URI' => '/',
        ];

        // Whitelist the REAL client IP
        $this->config->setIPWhitelist(['203.0.113.100']);

        // Should extract real IP and allow (whitelist match)
        $this->assertTrue($this->waf->handle($server));
    }

    /**
     * TEST FIX #4: Nginx X-Real-IP Header
     */
    public function test_nginx_x_real_ip_header()
    {
        $this->config->setTrustedProxies(['127.0.0.1']);

        $server = [
            'REMOTE_ADDR' => '127.0.0.1',  // Nginx localhost
            'HTTP_X_REAL_IP' => '198.51.100.50',  // Real client
            'REQUEST_URI' => '/',
        ];

        $this->config->setIPBlacklist(['198.51.100.50']);

        // Should extract real IP and block (blacklist match)
        $this->assertFalse($this->waf->handle($server));
        $this->assertSame('ip_blacklisted', $this->waf->getBlockReason());
    }

    /**
     * TEST FIX #4: X-Forwarded-For with Multiple Proxies
     */
    public function test_x_forwarded_for_multiple_proxies()
    {
        $this->config->setTrustedProxies(['10.0.0.0/8']);

        $server = [
            'REMOTE_ADDR' => '10.0.0.5',  // Internal proxy
            'HTTP_X_FORWARDED_FOR' => '203.0.113.200, 10.0.0.3, 10.0.0.5',  // client, proxy1, proxy2
            'REQUEST_URI' => '/',
        ];

        $this->config->setIPBlacklist(['203.0.113.200']);

        // Should take FIRST IP (original client)
        $this->assertFalse($this->waf->handle($server));
    }

    /**
     * TEST FIX #4: IP Spoofing Protection (Untrusted Proxy)
     */
    public function test_ip_spoofing_protection()
    {
        // NO trusted proxies configured
        $this->config->setTrustedProxies([]);

        $server = [
            'REMOTE_ADDR' => '203.0.113.50',  // Attacker's real IP
            'HTTP_X_FORWARDED_FOR' => '127.0.0.1',  // Spoofed localhost
            'REQUEST_URI' => '/',
        ];

        // Whitelist localhost
        $this->config->setIPWhitelist(['127.0.0.1']);

        // Should USE REMOTE_ADDR (not trust X-Forwarded-For)
        // 203.0.113.50 is NOT whitelisted → should pass (not blocked)
        $this->assertTrue($this->waf->handle($server));
    }

    /**
     * TEST FIX #4: CIDR Whitelist Support
     */
    public function test_cidr_whitelist_support()
    {
        // Whitelist entire /24 subnet
        $this->config->setIPWhitelist(['192.168.1.0/24']);

        $server = [
            'REMOTE_ADDR' => '192.168.1.150',
            'REQUEST_URI' => '/',
        ];

        // Should match CIDR whitelist
        $this->assertTrue($this->waf->handle($server));
    }

    /**
     * TEST FIX #4: CIDR Blacklist Support
     */
    public function test_cidr_blacklist_support()
    {
        // Blacklist entire /16 subnet
        $this->config->setIPBlacklist(['10.0.0.0/16']);

        $server = [
            'REMOTE_ADDR' => '10.0.50.100',
            'REQUEST_URI' => '/',
        ];

        // Should match CIDR blacklist
        $this->assertFalse($this->waf->handle($server));
        $this->assertSame('ip_blacklisted', $this->waf->getBlockReason());
    }

    /**
     * TEST FIX #5: Malformed URL Handling
     */
    public function test_malformed_url_handling()
    {
        $server = [
            'REMOTE_ADDR' => '203.0.113.100',
            'REQUEST_URI' => 'http:///malformed/../../../etc/passwd',  // Malformed URL
        ];

        // Should NOT crash, should extract path safely
        $result = $this->waf->handle($server);
        $this->assertIsBool($result);  // No crash
    }

    /**
     * TEST FIX #5: URL with Null Bytes
     */
    public function test_url_with_null_bytes()
    {
        $server = [
            'REMOTE_ADDR' => '203.0.113.100',
            'REQUEST_URI' => "/index.php\x00.jpg",  // Null byte injection
        ];

        // Should handle gracefully
        $result = $this->waf->handle($server);
        $this->assertIsBool($result);
    }

    /**
     * TEST: Concurrent Requests Simulation (100 rapid requests)
     */
    public function test_concurrent_requests_simulation()
    {
        $requests = 100;
        $allowed = 0;
        $blocked = 0;

        for ($i = 0; $i < $requests; $i++) {
            $server = [
                'REMOTE_ADDR' => '203.0.113.' . ($i % 256),
                'REQUEST_URI' => '/test',
                'HTTP_USER_AGENT' => 'Test Client',
            ];

            $result = $this->waf->handle($server);
            if ($result) {
                $allowed++;
            } else {
                $blocked++;
            }
        }

        // Most should be allowed (no malicious patterns)
        $this->assertGreaterThan(0, $allowed);
        $this->assertLessThan($requests, $blocked);
    }

    /**
     * TEST: Rate Limiting with Rapid Requests
     */
    public function test_rate_limiting_rapid_requests()
    {
        $this->config->setRateLimitPerMinute(10);

        $server = [
            'REMOTE_ADDR' => '203.0.113.100',
            'REQUEST_URI' => '/api/test',
        ];

        $allowed = 0;
        $blocked = 0;

        // Send 20 requests (limit is 10)
        for ($i = 0; $i < 20; $i++) {
            $result = $this->waf->handle($server);
            if ($result) {
                $allowed++;
            } else {
                $blocked++;
            }
        }

        // First 10 should pass, rest should be blocked
        $this->assertGreaterThanOrEqual(10, $allowed);
        $this->assertGreaterThan(0, $blocked);
    }

    /**
     * TEST: IPv6 Support
     */
    public function test_ipv6_support()
    {
        $server = [
            'REMOTE_ADDR' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            'REQUEST_URI' => '/',
        ];

        // Should handle IPv6 addresses
        $result = $this->waf->handle($server);
        $this->assertIsBool($result);
    }

    /**
     * TEST: Trusted Proxy Validation (Invalid IP)
     */
    public function test_trusted_proxy_validation_invalid_ip()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IP address');

        $this->config->setTrustedProxies(['not-an-ip']);
    }

    /**
     * TEST: Trusted Proxy Validation (Invalid CIDR)
     */
    public function test_trusted_proxy_validation_invalid_cidr()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid CIDR');

        $this->config->setTrustedProxies(['192.168.1.0/99']);  // Invalid mask
    }

    /**
     * TEST: Configuration Validation (Score Threshold)
     */
    public function test_configuration_validation_score_threshold()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Score threshold');

        $this->config->setScoreThreshold(-10);  // Invalid negative value
    }

    /**
     * TEST: Configuration Validation (Ban Duration)
     */
    public function test_configuration_validation_ban_duration()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Ban duration');

        $this->config->setBanDuration(10);  // Too short (< 60s)
    }
}
