<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Health;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Health\CallableHealthCheck;
use Senza1dio\SecurityShield\Health\CheckResult;
use Senza1dio\SecurityShield\Health\HealthCheck;
use Senza1dio\SecurityShield\Health\HealthStatus;

class HealthCheckTest extends TestCase
{
    public function testHealthyWhenAllChecksPass(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('database', new CallableHealthCheck(
            fn() => CheckResult::healthy('Connected')
        ));
        $healthCheck->addCheck('cache', new CallableHealthCheck(
            fn() => CheckResult::healthy('Connected')
        ));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::HEALTHY, $result->status);
        $this->assertTrue($result->isHealthy());
    }

    public function testDegradedWhenOneCheckDegraded(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('database', new CallableHealthCheck(
            fn() => CheckResult::healthy('Connected')
        ));
        $healthCheck->addCheck('cache', new CallableHealthCheck(
            fn() => CheckResult::degraded('High latency')
        ));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::DEGRADED, $result->status);
        $this->assertFalse($result->isHealthy());
        $this->assertTrue($result->isDegraded());
    }

    public function testUnhealthyWhenOneCheckFails(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('database', new CallableHealthCheck(
            fn() => CheckResult::unhealthy('Connection refused')
        ));
        $healthCheck->addCheck('cache', new CallableHealthCheck(
            fn() => CheckResult::healthy('Connected')
        ));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
        $this->assertFalse($result->isHealthy());
        $this->assertTrue($result->isUnhealthy());
    }

    public function testLivenessAlwaysHealthyByDefault(): void
    {
        $healthCheck = new HealthCheck();

        $result = $healthCheck->liveness();

        $this->assertSame(HealthStatus::HEALTHY, $result->status);
    }

    public function testLivenessWithCustomCheck(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addLivenessCheck('deadlock', new CallableHealthCheck(
            fn() => CheckResult::unhealthy('Deadlock detected')
        ));

        $result = $healthCheck->liveness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
    }

    public function testComponentHealthIncluded(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('database', new CallableHealthCheck(
            fn() => CheckResult::healthy('Connected', ['version' => '8.0'])
        ));

        $result = $healthCheck->readiness();

        $this->assertArrayHasKey('database', $result->components);
        $this->assertSame(HealthStatus::HEALTHY, $result->components['database']->status);
        $this->assertSame('Connected', $result->components['database']->message);
        $this->assertSame(['version' => '8.0'], $result->components['database']->metadata);
    }

    public function testTimeout(): void
    {
        $healthCheck = new HealthCheck(timeout: 0.1);
        $healthCheck->addCheck('slow', new CallableHealthCheck(
            function () {
                usleep(500000); // 0.5 seconds
                return CheckResult::healthy('Eventually connected');
            }
        ));

        $result = $healthCheck->readiness();

        // Should timeout and be marked unhealthy
        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
    }

    public function testExceptionHandling(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('unstable', new CallableHealthCheck(
            fn() => throw new \RuntimeException('Connection failed')
        ));

        $result = $healthCheck->readiness();

        $this->assertSame(HealthStatus::UNHEALTHY, $result->status);
        $this->assertStringContainsString('Connection failed', $result->components['unstable']->message);
    }

    public function testResultToArray(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('test', new CallableHealthCheck(
            fn() => CheckResult::healthy('OK')
        ));

        $result = $healthCheck->readiness();
        $array = $result->toArray();

        $this->assertArrayHasKey('status', $array);
        $this->assertArrayHasKey('timestamp', $array);
        $this->assertArrayHasKey('components', $array);
        $this->assertArrayHasKey('duration_ms', $array);
    }

    public function testToJson(): void
    {
        $healthCheck = new HealthCheck();
        $healthCheck->addCheck('test', new CallableHealthCheck(
            fn() => CheckResult::healthy('OK')
        ));

        $result = $healthCheck->readiness();
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertSame('healthy', $decoded['status']);
    }
}
