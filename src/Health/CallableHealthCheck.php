<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Wrapper for callable health checks
 */
class CallableHealthCheck implements HealthCheckInterface
{
    /** @var callable(): bool */
    private $callable;

    /**
     * @param callable(): bool $callable Returns true if healthy
     */
    public function __construct(callable $callable)
    {
        $this->callable = $callable;
    }

    public function check(): CheckResult
    {
        try {
            $result = ($this->callable)();
            return $result ? CheckResult::healthy() : CheckResult::unhealthy('Check returned false');
        } catch (\Throwable $e) {
            return CheckResult::unhealthy($e->getMessage());
        }
    }
}
