<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly\Detectors;

use Senza1dio\SecurityShield\Anomaly\Anomaly;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\DetectorInterface;

/**
 * Pattern Anomaly Detector
 *
 * Detects unusual request patterns (endpoints, methods, sequences).
 *
 * USAGE:
 * ```php
 * $detector = new PatternDetector();
 *
 * // Train with normal patterns
 * $detector->train([
 *     ['method' => 'GET', 'path' => '/api/users', 'user_agent' => 'Mozilla/5.0...'],
 *     ['method' => 'POST', 'path' => '/api/login', 'user_agent' => 'Mozilla/5.0...'],
 * ]);
 *
 * // Analyze new request
 * $anomalies = $detector->analyze([
 *     'method' => 'DELETE',
 *     'path' => '/api/admin/users/all',
 *     'user_agent' => 'curl/7.64.1',
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Anomaly\Detectors
 */
class PatternDetector implements DetectorInterface
{
    /** @var array<string, int> */
    private array $methodCounts = [];

    /** @var array<string, int> */
    private array $pathPrefixCounts = [];

    /** @var array<string, int> */
    private array $userAgentCounts = [];

    private int $totalSamples = 0;
    private bool $trained = false;

    private float $rarityThreshold;

    /**
     * @param float $rarityThreshold Minimum occurrence ratio to be considered normal
     */
    public function __construct(float $rarityThreshold = 0.01)
    {
        $this->rarityThreshold = $rarityThreshold;
    }

    public function getName(): string
    {
        return 'pattern';
    }

    public function analyze(array $data): array
    {
        if (!$this->trained) {
            return [];
        }

        $anomalies = [];

        // Check HTTP method
        if (isset($data['method'])) {
            $method = strtoupper($data['method']);
            $methodRarity = $this->calculateRarity($method, $this->methodCounts);

            if ($methodRarity > 0.8) {
                $anomalies[] = new Anomaly(
                    AnomalyType::PATTERN_ANOMALY,
                    $methodRarity * 0.7,
                    "Unusual HTTP method: {$method}",
                    [
                        'pattern_type' => 'http_method',
                        'method' => $method,
                        'rarity_score' => round($methodRarity, 2),
                    ]
                );
            }
        }

        // Check path pattern
        if (isset($data['path'])) {
            $pathPrefix = $this->extractPathPrefix($data['path']);
            $pathRarity = $this->calculateRarity($pathPrefix, $this->pathPrefixCounts);

            if ($pathRarity > 0.7) {
                $anomalies[] = new Anomaly(
                    AnomalyType::PATTERN_ANOMALY,
                    $pathRarity * 0.6,
                    "Unusual path pattern: {$data['path']}",
                    [
                        'pattern_type' => 'path',
                        'path' => $data['path'],
                        'path_prefix' => $pathPrefix,
                        'rarity_score' => round($pathRarity, 2),
                    ]
                );
            }
        }

        // Check user agent
        if (isset($data['user_agent'])) {
            $uaCategory = $this->categorizeUserAgent($data['user_agent']);
            $uaRarity = $this->calculateRarity($uaCategory, $this->userAgentCounts);

            if ($uaRarity > 0.8) {
                $anomalies[] = new Anomaly(
                    AnomalyType::USER_AGENT_ANOMALY,
                    $uaRarity * 0.5,
                    "Unusual user agent category: {$uaCategory}",
                    [
                        'pattern_type' => 'user_agent',
                        'user_agent' => $data['user_agent'],
                        'category' => $uaCategory,
                        'rarity_score' => round($uaRarity, 2),
                    ]
                );
            }
        }

        // Check suspicious patterns
        $suspiciousPatterns = $this->checkSuspiciousPatterns($data);
        $anomalies = array_merge($anomalies, $suspiciousPatterns);

        return $anomalies;
    }

    public function train(array $historicalData): void
    {
        $this->methodCounts = [];
        $this->pathPrefixCounts = [];
        $this->userAgentCounts = [];
        $this->totalSamples = count($historicalData);

        foreach ($historicalData as $sample) {
            if (isset($sample['method'])) {
                $method = strtoupper($sample['method']);
                $this->methodCounts[$method] = ($this->methodCounts[$method] ?? 0) + 1;
            }

            if (isset($sample['path'])) {
                $prefix = $this->extractPathPrefix($sample['path']);
                $this->pathPrefixCounts[$prefix] = ($this->pathPrefixCounts[$prefix] ?? 0) + 1;
            }

            if (isset($sample['user_agent'])) {
                $category = $this->categorizeUserAgent($sample['user_agent']);
                $this->userAgentCounts[$category] = ($this->userAgentCounts[$category] ?? 0) + 1;
            }
        }

        $this->trained = $this->totalSamples >= 10;
    }

    public function isReady(): bool
    {
        return $this->trained;
    }

    /**
     * Calculate how rare a value is (0 = common, 1 = never seen)
     *
     * @param string $value
     * @param array<string, int> $counts
     */
    private function calculateRarity(string $value, array $counts): float
    {
        if ($this->totalSamples === 0) {
            return 0.0;
        }

        $count = $counts[$value] ?? 0;
        $ratio = $count / $this->totalSamples;

        if ($count === 0) {
            return 1.0; // Never seen
        }

        if ($ratio >= $this->rarityThreshold) {
            return 0.0; // Common enough
        }

        // Scale rarity based on how far below threshold
        return 1 - ($ratio / $this->rarityThreshold);
    }

    /**
     * Extract path prefix for pattern matching
     */
    private function extractPathPrefix(string $path): string
    {
        // Handle empty path
        if ($path === '' || $path === '/') {
            return '/';
        }

        // Remove query string
        $pathWithoutQuery = strtok($path, '?');
        $path = ($pathWithoutQuery !== false && $pathWithoutQuery !== '') ? $pathWithoutQuery : '/';

        // Get first 2 path segments
        $segments = array_filter(explode('/', $path), fn($s) => $s !== '');

        if (empty($segments)) {
            return '/';
        }

        $segments = array_slice(array_values($segments), 0, 2);

        return '/' . implode('/', $segments);
    }

    /**
     * Categorize user agent into groups
     */
    private function categorizeUserAgent(string $userAgent): string
    {
        $ua = strtolower($userAgent);

        if (empty($userAgent)) {
            return 'empty';
        }

        // Known bots
        $bots = ['googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'slurp', 'baiduspider'];
        foreach ($bots as $bot) {
            if (str_contains($ua, $bot)) {
                return 'search_bot';
            }
        }

        // Common browsers
        if (str_contains($ua, 'chrome') && !str_contains($ua, 'edge')) {
            return 'chrome';
        }

        if (str_contains($ua, 'firefox')) {
            return 'firefox';
        }

        if (str_contains($ua, 'safari') && !str_contains($ua, 'chrome')) {
            return 'safari';
        }

        if (str_contains($ua, 'edge')) {
            return 'edge';
        }

        // CLI tools
        if (str_contains($ua, 'curl')) {
            return 'curl';
        }

        if (str_contains($ua, 'wget')) {
            return 'wget';
        }

        if (str_contains($ua, 'python')) {
            return 'python';
        }

        // Mobile
        if (str_contains($ua, 'mobile') || str_contains($ua, 'android') || str_contains($ua, 'iphone')) {
            return 'mobile';
        }

        return 'other';
    }

    /**
     * Check for suspicious patterns
     *
     * @param array<string, mixed> $data
     * @return array<int, Anomaly>
     */
    private function checkSuspiciousPatterns(array $data): array
    {
        $anomalies = [];
        $path = $data['path'] ?? '';

        // Directory traversal patterns
        if (preg_match('/\.\.\/|\.\.\\\\/', $path)) {
            $anomalies[] = new Anomaly(
                AnomalyType::PATTERN_ANOMALY,
                0.9,
                "Directory traversal pattern detected in path",
                [
                    'pattern_type' => 'directory_traversal',
                    'path' => $path,
                ]
            );
        }

        // Null byte injection
        if (str_contains($path, '%00') || str_contains($path, "\0")) {
            $anomalies[] = new Anomaly(
                AnomalyType::PATTERN_ANOMALY,
                0.95,
                "Null byte injection pattern detected",
                [
                    'pattern_type' => 'null_byte',
                    'path' => $path,
                ]
            );
        }

        // Sensitive file access
        $sensitivePatterns = [
            '/\.env/i',
            '/wp-config\.php/i',
            '/\.git\//i',
            '/\.htaccess/i',
            '/web\.config/i',
            '/composer\.json/i',
            '/package\.json/i',
        ];

        foreach ($sensitivePatterns as $pattern) {
            if (preg_match($pattern, $path)) {
                $anomalies[] = new Anomaly(
                    AnomalyType::PATTERN_ANOMALY,
                    0.85,
                    "Sensitive file access attempt detected",
                    [
                        'pattern_type' => 'sensitive_file',
                        'path' => $path,
                    ]
                );
                break;
            }
        }

        return $anomalies;
    }
}
