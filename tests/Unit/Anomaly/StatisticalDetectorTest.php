<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Anomaly;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Anomaly\AnomalyType;
use Senza1dio\SecurityShield\Anomaly\Detectors\StatisticalDetector;

class StatisticalDetectorTest extends TestCase
{
    public function testNotReadyBeforeTraining(): void
    {
        $detector = new StatisticalDetector(['metric1']);

        $this->assertFalse($detector->isReady());
    }

    public function testReadyAfterTraining(): void
    {
        $detector = new StatisticalDetector(['requests']);
        $detector->train([
            ['requests' => 100],
            ['requests' => 110],
            ['requests' => 105],
        ]);

        $this->assertTrue($detector->isReady());
    }

    public function testNoAnomalyForNormalValue(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 3.0);
        $detector->setBaseline('requests', 100, 10);

        $anomalies = $detector->analyze(['requests' => 105]);

        $this->assertEmpty($anomalies);
    }

    public function testDetectsHighValueAnomaly(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        // 150 is 5 standard deviations above mean (z-score = 5)
        $anomalies = $detector->analyze(['requests' => 150]);

        $this->assertCount(1, $anomalies);
        $this->assertSame(AnomalyType::STATISTICAL_ANOMALY, $anomalies[0]->getType());
        $this->assertSame('above', $anomalies[0]->getContextValue('direction'));
    }

    public function testDetectsLowValueAnomaly(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        // 50 is 5 standard deviations below mean (z-score = -5)
        $anomalies = $detector->analyze(['requests' => 50]);

        $this->assertCount(1, $anomalies);
        $this->assertSame('below', $anomalies[0]->getContextValue('direction'));
    }

    public function testMultipleMetrics(): void
    {
        $detector = new StatisticalDetector(['requests', 'latency'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);
        $detector->setBaseline('latency', 0.1, 0.02);

        // Normal requests, high latency
        $anomalies = $detector->analyze([
            'requests' => 105,
            'latency' => 0.5, // 20 std devs above
        ]);

        $this->assertCount(1, $anomalies);
        $this->assertSame('latency', $anomalies[0]->getContextValue('metric'));
    }

    public function testTrainingCalculatesBaseline(): void
    {
        $detector = new StatisticalDetector(['value']);
        $detector->train([
            ['value' => 10],
            ['value' => 20],
            ['value' => 30],
            ['value' => 40],
            ['value' => 50],
        ]);

        $baseline = $detector->getBaseline('value');

        $this->assertNotNull($baseline);
        $this->assertEqualsWithDelta(30.0, $baseline['mean'], 0.01);
        $this->assertGreaterThan(0, $baseline['stddev']);
    }

    public function testIgnoresNullValues(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        $anomalies = $detector->analyze(['requests' => null]);

        $this->assertEmpty($anomalies);
    }

    public function testIgnoresUnknownMetrics(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        $anomalies = $detector->analyze(['unknown_metric' => 1000]);

        $this->assertEmpty($anomalies);
    }

    public function testAnomalyScoreRange(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        $anomalies = $detector->analyze(['requests' => 200]);

        $this->assertCount(1, $anomalies);
        $score = $anomalies[0]->getScore();
        $this->assertGreaterThanOrEqual(0.0, $score);
        $this->assertLessThanOrEqual(1.0, $score);
    }

    public function testAnomalyContainsContext(): void
    {
        $detector = new StatisticalDetector(['requests'], zScoreThreshold: 2.0);
        $detector->setBaseline('requests', 100, 10);

        $anomalies = $detector->analyze(['requests' => 200]);

        $context = $anomalies[0]->getContext();

        $this->assertArrayHasKey('metric', $context);
        $this->assertArrayHasKey('value', $context);
        $this->assertArrayHasKey('mean', $context);
        $this->assertArrayHasKey('stddev', $context);
        $this->assertArrayHasKey('z_score', $context);
    }
}
