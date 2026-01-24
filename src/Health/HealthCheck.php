<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health;

/**
 * Health Check System.
 *
 * Enterprise health monitoring for Kubernetes, Docker, and load balancers.
 *
 * PROBE TYPES:
 * - Liveness: Is the process alive? (restart if fails)
 * - Readiness: Can it accept traffic? (remove from LB if fails)
 * - Startup: Has it finished initializing? (wait before liveness)
 *
 * KUBERNETES INTEGRATION:
 * ```yaml
 * livenessProbe:
 *   httpGet:
 *     path: /health/live
 *     port: 8080
 *   initialDelaySeconds: 3
 *   periodSeconds: 10
 *
 * readinessProbe:
 *   httpGet:
 *     path: /health/ready
 *     port: 8080
 *   initialDelaySeconds: 5
 *   periodSeconds: 5
 * ```
 *
 * USAGE:
 * ```php
 * $health = new HealthCheck();
 *
 * $health
 *     ->addCheck('redis', new RedisHealthCheck($redis))
 *     ->addCheck('database', new DatabaseHealthCheck($pdo))
 *     ->addCheck('geoip', new GeoIPHealthCheck($geoipService));
 *
 * // In your health endpoint
 * $result = $health->check();
 *
 * http_response_code($result->isHealthy() ? 200 : 503);
 * header('Content-Type: application/json');
 * echo json_encode($result->toArray());
 * ```
 */
class HealthCheck
{
    /** @var array<string, HealthCheckInterface> */
    private array $checks = [];

    /** @var array<string, bool> */
    private array $criticalChecks = [];

    private ?int $cacheTTL = null;

    private ?HealthResult $cachedResult = null;

    private ?float $cachedAt = null;

    /**
     * Add a health check.
     *
     * @param string $name Unique name for this check
     * @param HealthCheckInterface $check The health check implementation
     * @param bool $critical If true, failure means system is unhealthy
     */
    public function addCheck(string $name, HealthCheckInterface $check, bool $critical = true): self
    {
        $this->checks[$name] = $check;
        $this->criticalChecks[$name] = $critical;

        return $this;
    }

    /**
     * Add a simple callable check.
     *
     * @param string $name Check name
     * @param callable(): bool $check Returns true if healthy
     * @param bool $critical If true, failure means unhealthy
     */
    public function addSimpleCheck(string $name, callable $check, bool $critical = true): self
    {
        $this->checks[$name] = new CallableHealthCheck($check);
        $this->criticalChecks[$name] = $critical;

        return $this;
    }

    /**
     * Enable caching of health check results.
     *
     * @param int $ttlSeconds Cache TTL in seconds
     */
    public function enableCache(int $ttlSeconds): self
    {
        $this->cacheTTL = $ttlSeconds;

        return $this;
    }

    /**
     * Run all health checks.
     *
     * @param bool $forceRefresh Bypass cache
     */
    public function check(bool $forceRefresh = false): HealthResult
    {
        // Check cache
        if (!$forceRefresh && $this->isCacheValid() && $this->cachedResult !== null) {
            return $this->cachedResult;
        }

        $componentResults = [];
        $overallHealthy = true;
        $overallStatus = HealthStatus::HEALTHY;

        foreach ($this->checks as $name => $check) {
            $startTime = microtime(true);

            try {
                $componentResult = $check->check();
                $duration = (microtime(true) - $startTime) * 1000; // ms

                $componentResults[$name] = new ComponentHealth(
                    name: $name,
                    status: $componentResult->status,
                    message: $componentResult->message,
                    duration: $duration,
                    metadata: $componentResult->metadata,
                    critical: $this->criticalChecks[$name] ?? true,
                );

            } catch (\Throwable $e) {
                $duration = (microtime(true) - $startTime) * 1000;

                $componentResults[$name] = new ComponentHealth(
                    name: $name,
                    status: HealthStatus::UNHEALTHY,
                    message: $e->getMessage(),
                    duration: $duration,
                    metadata: ['exception' => get_class($e)],
                    critical: $this->criticalChecks[$name] ?? true,
                );
            }

            // Update overall status
            $componentStatus = $componentResults[$name]->status;
            $isCritical = $this->criticalChecks[$name] ?? true;

            if ($componentStatus === HealthStatus::UNHEALTHY && $isCritical) {
                $overallHealthy = false;
                $overallStatus = HealthStatus::UNHEALTHY;
            } elseif ($componentStatus === HealthStatus::DEGRADED && $overallStatus !== HealthStatus::UNHEALTHY) {
                $overallStatus = HealthStatus::DEGRADED;
            }
        }

        $result = new HealthResult(
            status: $overallStatus,
            components: $componentResults,
            timestamp: time(),
        );

        // Cache result
        if ($this->cacheTTL !== null) {
            $this->cachedResult = $result;
            $this->cachedAt = microtime(true);
        }

        return $result;
    }

    /**
     * Run liveness check (minimal, fast).
     *
     * Only checks if the process is alive, not dependencies.
     */
    public function liveness(): HealthResult
    {
        return new HealthResult(
            status: HealthStatus::HEALTHY,
            components: [],
            timestamp: time(),
        );
    }

    /**
     * Run readiness check (all checks).
     *
     * Full check of all dependencies.
     */
    public function readiness(): HealthResult
    {
        return $this->check();
    }

    /**
     * Get check names.
     *
     * @return array<string>
     */
    public function getCheckNames(): array
    {
        return array_keys($this->checks);
    }

    /**
     * Clear cached result.
     */
    public function clearCache(): void
    {
        $this->cachedResult = null;
        $this->cachedAt = null;
    }

    private function isCacheValid(): bool
    {
        if ($this->cacheTTL === null || $this->cachedResult === null || $this->cachedAt === null) {
            return false;
        }

        $elapsed = microtime(true) - $this->cachedAt;

        return $elapsed < $this->cacheTTL;
    }
}
