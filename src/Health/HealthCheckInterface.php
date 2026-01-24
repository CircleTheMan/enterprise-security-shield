<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Interface for health check implementations
 */
interface HealthCheckInterface
{
    /**
     * Perform the health check
     *
     * @return CheckResult Result of the check
     */
    public function check(): CheckResult;
}
