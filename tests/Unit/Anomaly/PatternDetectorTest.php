<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Anomaly;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\Detectors\PatternDetector;

class PatternDetectorTest extends TestCase
{
    public function testNotReadyBeforeTraining(): void
    {
        $detector = new PatternDetector();

        $this->assertFalse($detector->isReady());
    }

    public function testReadyAfterTraining(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $this->assertTrue($detector->isReady());
    }

    public function testNoAnomalyForNormalRequest(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'GET',
            'path' => '/api/users/123',
            'user_agent' => 'Mozilla/5.0 Chrome/100.0',
        ]);

        $this->assertEmpty($anomalies);
    }

    public function testDetectsUnusualHttpMethod(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'TRACE',
            'path' => '/api/users',
        ]);

        $patternAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getContextValue('pattern_type') === 'http_method'
        );

        $this->assertNotEmpty($patternAnomalies);
    }

    public function testDetectsUnusualPath(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'GET',
            'path' => '/admin/secret/config',
        ]);

        $patternAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getContextValue('pattern_type') === 'path'
        );

        $this->assertNotEmpty($patternAnomalies);
    }

    public function testDetectsUnusualUserAgent(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'GET',
            'path' => '/api/users',
            'user_agent' => 'python-requests/2.28.0',
        ]);

        $uaAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getType() === AnomalyType::USER_AGENT_ANOMALY
        );

        $this->assertNotEmpty($uaAnomalies);
    }

    public function testDetectsDirectoryTraversal(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'GET',
            'path' => '/api/../../../etc/passwd',
        ]);

        $traversalAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getContextValue('pattern_type') === 'directory_traversal'
        );

        $this->assertNotEmpty($traversalAnomalies);
        $this->assertGreaterThanOrEqual(0.9, reset($traversalAnomalies)->getScore());
    }

    public function testDetectsNullByteInjection(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $anomalies = $detector->analyze([
            'method' => 'GET',
            'path' => '/api/file.php%00.jpg',
        ]);

        $nullByteAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getContextValue('pattern_type') === 'null_byte'
        );

        $this->assertNotEmpty($nullByteAnomalies);
        $this->assertGreaterThanOrEqual(0.95, reset($nullByteAnomalies)->getScore());
    }

    public function testDetectsSensitiveFileAccess(): void
    {
        $detector = new PatternDetector();
        $detector->train($this->getTrainingData());

        $sensitiveFiles = [
            '/.env',
            '/wp-config.php',
            '/.git/config',
            '/.htaccess',
        ];

        foreach ($sensitiveFiles as $file) {
            $anomalies = $detector->analyze([
                'method' => 'GET',
                'path' => $file,
            ]);

            $sensitiveAnomalies = array_filter(
                $anomalies,
                fn($a) => $a->getContextValue('pattern_type') === 'sensitive_file'
            );

            $this->assertNotEmpty($sensitiveAnomalies, "Should detect access to {$file}");
        }
    }

    public function testCategorizesUserAgents(): void
    {
        $detector = new PatternDetector();
        $data = array_merge(
            $this->getTrainingData(),
            array_fill(0, 50, ['user_agent' => 'curl/7.64.1'])
        );
        $detector->train($data);

        // curl is common now, should not be anomaly
        $anomalies = $detector->analyze([
            'user_agent' => 'curl/7.64.1',
        ]);

        $curlAnomalies = array_filter(
            $anomalies,
            fn($a) => $a->getType() === AnomalyType::USER_AGENT_ANOMALY
        );

        $this->assertEmpty($curlAnomalies);
    }

    /**
     * @return array<int, array<string, string>>
     */
    private function getTrainingData(): array
    {
        $data = [];

        // Normal traffic patterns
        $methods = ['GET', 'POST', 'GET', 'GET', 'GET', 'PUT', 'DELETE'];
        $paths = ['/api/users', '/api/products', '/api/orders', '/api/auth'];
        $userAgents = [
            'Mozilla/5.0 Chrome/100.0',
            'Mozilla/5.0 Firefox/98.0',
            'Mozilla/5.0 Safari/605.1.15',
        ];

        for ($i = 0; $i < 100; $i++) {
            $data[] = [
                'method' => $methods[array_rand($methods)],
                'path' => $paths[array_rand($paths)] . '/' . rand(1, 1000),
                'user_agent' => $userAgents[array_rand($userAgents)],
            ];
        }

        return $data;
    }
}
