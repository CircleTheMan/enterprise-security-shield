<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Utils;

/**
 * IP Utilities - Centralized IP Address Operations
 *
 * Provides thread-safe, well-tested utilities for IP address handling:
 * - CIDR range matching (IPv4 and IPv6)
 * - IP validation and normalization
 * - Proxy header extraction
 * - Private/reserved IP detection
 *
 * DESIGN PRINCIPLES:
 * - Zero external dependencies
 * - Pure functions (no side effects)
 * - Defensive programming (validates all inputs)
 * - Performance optimized (bitwise operations)
 *
 * USAGE:
 * ```php
 * // Check if IP is in CIDR range
 * if (IPUtils::isInCIDR('192.168.1.50', '192.168.1.0/24')) {
 *     // IP is in range
 * }
 *
 * // Extract real client IP from proxy headers
 * $clientIP = IPUtils::extractClientIP($_SERVER, ['173.245.48.0/20']);
 *
 * // Check if IP is private/reserved
 * if (IPUtils::isPrivateIP('10.0.0.1')) {
 *     // Private network
 * }
 * ```
 *
 * @package Senza1dio\SecurityShield\Utils
 */
final class IPUtils
{
    /**
     * Private IPv4 ranges (RFC 1918 + loopback + link-local)
     */
    private const PRIVATE_IPV4_RANGES = [
        '10.0.0.0/8',       // Class A private
        '172.16.0.0/12',    // Class B private
        '192.168.0.0/16',   // Class C private
        '127.0.0.0/8',      // Loopback
        '169.254.0.0/16',   // Link-local
        '0.0.0.0/8',        // Current network
        '100.64.0.0/10',    // Carrier-grade NAT
        '192.0.0.0/24',     // IETF Protocol Assignments
        '192.0.2.0/24',     // TEST-NET-1
        '198.51.100.0/24',  // TEST-NET-2
        '203.0.113.0/24',   // TEST-NET-3
        '224.0.0.0/4',      // Multicast
        '240.0.0.0/4',      // Reserved for future use
        '255.255.255.255/32', // Broadcast
    ];

    /**
     * Private IPv6 prefixes
     */
    private const PRIVATE_IPV6_PREFIXES = [
        '::1',          // Loopback
        'fc00::/7',     // Unique local (fc00::/8 + fd00::/8)
        'fe80::/10',    // Link-local
        'ff00::/8',     // Multicast
        '::',           // Unspecified
        '::ffff:0:0/96', // IPv4-mapped
        '64:ff9b::/96', // NAT64
        '100::/64',     // Discard prefix
        '2001::/32',    // Teredo
        '2001:db8::/32', // Documentation
        '2002::/16',    // 6to4
    ];

    /**
     * Check if IP address is within a CIDR range
     *
     * Supports both IPv4 and IPv6 addresses with automatic protocol detection.
     *
     * EXAMPLES:
     * - isInCIDR('192.168.1.50', '192.168.1.0/24') → true
     * - isInCIDR('10.0.0.1', '192.168.1.0/24') → false
     * - isInCIDR('2001:db8::1', '2001:db8::/32') → true
     *
     * PERFORMANCE:
     * - IPv4: ~0.1ms (bitwise operations)
     * - IPv6: ~0.2ms (binary comparison)
     *
     * @param string $ip IP address to check
     * @param string $cidr CIDR notation (e.g., '192.168.1.0/24' or '2001:db8::/32')
     * @return bool True if IP is within CIDR range
     */
    public static function isInCIDR(string $ip, string $cidr): bool
    {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Parse CIDR notation
        if (!str_contains($cidr, '/')) {
            // Exact match (no mask)
            return $ip === $cidr;
        }

        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$subnet, $maskStr] = $parts;
        $mask = filter_var($maskStr, FILTER_VALIDATE_INT);

        if ($mask === false) {
            return false;
        }

        // Validate subnet
        if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Determine IP version
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        $isSubnetIPv6 = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

        // IP and subnet must be same protocol
        if ($isIPv6 !== $isSubnetIPv6) {
            return false;
        }

        if ($isIPv6) {
            return self::ipv6InCIDR($ip, $subnet, $mask);
        }

        return self::ipv4InCIDR($ip, $subnet, $mask);
    }

    /**
     * Check if IPv4 address is within CIDR range
     *
     * @param string $ip IPv4 address
     * @param string $subnet IPv4 subnet
     * @param int $mask CIDR mask (0-32)
     * @return bool True if IP is in range
     */
    private static function ipv4InCIDR(string $ip, string $subnet, int $mask): bool
    {
        // Validate mask range
        if ($mask < 0 || $mask > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        // Handle edge case: /0 matches everything
        if ($mask === 0) {
            return true;
        }

        // Calculate network mask using bitwise operations
        // -1 in PHP is all 1s in binary, shift left creates the mask
        $maskLong = -1 << (32 - $mask);

        // Apply mask to both IPs and compare network portions
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }

    /**
     * Check if IPv6 address is within CIDR range
     *
     * Uses binary string comparison for accuracy with 128-bit addresses.
     *
     * @param string $ip IPv6 address
     * @param string $subnet IPv6 subnet
     * @param int $mask CIDR mask (0-128)
     * @return bool True if IP is in range
     */
    private static function ipv6InCIDR(string $ip, string $subnet, int $mask): bool
    {
        // Validate mask range
        if ($mask < 0 || $mask > 128) {
            return false;
        }

        // Handle edge case: /0 matches everything
        if ($mask === 0) {
            return true;
        }

        // Convert IPv6 to binary representation (16 bytes)
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // Calculate number of full bytes and remaining bits to compare
        $fullBytes = intdiv($mask, 8);
        $remainingBits = $mask % 8;

        // Compare full bytes
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBin[$i] !== $subnetBin[$i]) {
                return false;
            }
        }

        // Compare remaining bits in partial byte (if any)
        if ($remainingBits > 0 && $fullBytes < 16) {
            $ipByte = ord($ipBin[$fullBytes]);
            $subnetByte = ord($subnetBin[$fullBytes]);

            // Create mask for remaining bits (e.g., 5 bits → 11111000 = 0xF8)
            $bitMask = (0xFF << (8 - $remainingBits)) & 0xFF;

            if (($ipByte & $bitMask) !== ($subnetByte & $bitMask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if IP matches any CIDR range in a list
     *
     * @param string $ip IP address to check
     * @param array<string> $cidrs List of CIDR ranges
     * @return bool True if IP matches any range
     */
    public static function isInAnyCIDR(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::isInCIDR($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP address is private or reserved
     *
     * Detects:
     * - RFC 1918 private networks (10.x, 172.16-31.x, 192.168.x)
     * - Loopback (127.x, ::1)
     * - Link-local (169.254.x, fe80::)
     * - Multicast, broadcast, reserved ranges
     *
     * @param string $ip IP address to check
     * @return bool True if private or reserved
     */
    public static function isPrivateIP(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Check IPv4 private ranges
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::isInAnyCIDR($ip, self::PRIVATE_IPV4_RANGES);
        }

        // Check IPv6 private prefixes
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipLower = strtolower($ip);

            // Check exact matches first
            if ($ipLower === '::1' || $ipLower === '::') {
                return true;
            }

            // Check prefixes
            foreach (self::PRIVATE_IPV6_PREFIXES as $prefix) {
                if (str_contains($prefix, '/')) {
                    if (self::isInCIDR($ip, $prefix)) {
                        return true;
                    }
                } else {
                    // Exact match check
                    if ($ipLower === strtolower($prefix)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Extract real client IP from request considering trusted proxies
     *
     * SECURITY: Only trusts proxy headers when REMOTE_ADDR matches a trusted proxy.
     * This prevents IP spoofing attacks where attackers set fake X-Forwarded-For headers.
     *
     * HEADER PRIORITY:
     * 1. CF-Connecting-IP (Cloudflare)
     * 2. X-Real-IP (Nginx)
     * 3. X-Forwarded-For (Standard proxy, first IP only)
     * 4. REMOTE_ADDR (Direct connection)
     *
     * @param array<string, mixed> $server $_SERVER superglobal
     * @param array<string> $trustedProxies List of trusted proxy IPs/CIDRs
     * @return string Resolved client IP address
     */
    public static function extractClientIP(array $server, array $trustedProxies = []): string
    {
        // Get REMOTE_ADDR
        $remoteAddrRaw = $server['REMOTE_ADDR'] ?? 'unknown';
        $remoteAddr = is_string($remoteAddrRaw) ? $remoteAddrRaw : 'unknown';

        // If no trusted proxies configured, use REMOTE_ADDR directly
        if (empty($trustedProxies)) {
            return $remoteAddr;
        }

        // Validate REMOTE_ADDR is a valid IP
        if (!filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
            return $remoteAddr;
        }

        // Check if REMOTE_ADDR is a trusted proxy
        if (!self::isInAnyCIDR($remoteAddr, $trustedProxies)) {
            // Not from trusted proxy - don't trust headers (spoofing protection)
            return $remoteAddr;
        }

        // Check proxy headers in priority order
        $headers = [
            'HTTP_CF_CONNECTING_IP',  // Cloudflare
            'HTTP_X_REAL_IP',         // Nginx
            'HTTP_X_FORWARDED_FOR',   // Standard proxy
        ];

        foreach ($headers as $header) {
            $value = $server[$header] ?? null;

            if (!is_string($value) || $value === '') {
                continue;
            }

            // X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2)
            // Take the FIRST IP (original client)
            if ($header === 'HTTP_X_FORWARDED_FOR') {
                $ips = array_map('trim', explode(',', $value));
                $value = $ips[0];
            }

            // Validate extracted IP
            if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
                return $value;
            }
        }

        // Fallback to REMOTE_ADDR
        return $remoteAddr;
    }

    /**
     * Validate IP address (IPv4 or IPv6)
     *
     * @param string $ip IP address to validate
     * @return bool True if valid IP address
     */
    public static function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Check if IP is IPv4
     *
     * @param string $ip IP address
     * @return bool True if IPv4
     */
    public static function isIPv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Check if IP is IPv6
     *
     * @param string $ip IP address
     * @return bool True if IPv6
     */
    public static function isIPv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Normalize IPv6 address to full form
     *
     * Expands compressed IPv6 addresses for consistent comparison.
     *
     * EXAMPLES:
     * - ::1 → 0000:0000:0000:0000:0000:0000:0000:0001
     * - 2001:db8::1 → 2001:0db8:0000:0000:0000:0000:0000:0001
     *
     * @param string $ip IPv6 address
     * @return string|null Normalized IPv6 or null if invalid
     */
    public static function normalizeIPv6(string $ip): ?string
    {
        if (!self::isIPv6($ip)) {
            return null;
        }

        $binary = inet_pton($ip);
        if ($binary === false) {
            return null;
        }

        // Convert binary to hex groups
        $hex = bin2hex($binary);
        $groups = str_split($hex, 4);

        return implode(':', $groups);
    }

    /**
     * Get IP version (4 or 6)
     *
     * @param string $ip IP address
     * @return int|null 4, 6, or null if invalid
     */
    public static function getIPVersion(string $ip): ?int
    {
        if (self::isIPv4($ip)) {
            return 4;
        }

        if (self::isIPv6($ip)) {
            return 6;
        }

        return null;
    }

    /**
     * Validate CIDR notation
     *
     * @param string $cidr CIDR string (e.g., '192.168.1.0/24')
     * @return bool True if valid CIDR notation
     */
    public static function isValidCIDR(string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return self::isValidIP($cidr);
        }

        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$ip, $maskStr] = $parts;

        if (!self::isValidIP($ip)) {
            return false;
        }

        $mask = filter_var($maskStr, FILTER_VALIDATE_INT);
        if ($mask === false) {
            return false;
        }

        // Check mask range based on IP version
        $maxMask = self::isIPv6($ip) ? 128 : 32;

        return $mask >= 0 && $mask <= $maxMask;
    }

    /**
     * Anonymize IP address for logging (GDPR compliance)
     *
     * Masks the last octet(s) to prevent personal identification.
     *
     * EXAMPLES:
     * - 192.168.1.100 → 192.168.1.0
     * - 2001:db8::1234:5678 → 2001:db8::0:0
     *
     * @param string $ip IP address
     * @return string Anonymized IP
     */
    public static function anonymize(string $ip): string
    {
        if (self::isIPv4($ip)) {
            // Mask last octet
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                $parts[3] = '0';
                return implode('.', $parts);
            }
        }

        if (self::isIPv6($ip)) {
            // Mask last 64 bits
            $binary = inet_pton($ip);
            if ($binary !== false) {
                // Zero out last 8 bytes
                $binary = substr($binary, 0, 8) . str_repeat("\0", 8);
                $result = inet_ntop($binary);
                return $result !== false ? $result : $ip;
            }
        }

        return $ip;
    }
}
