<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Health\Checks;

use Senza1dio\SecurityShield\Health\CheckResult;
use Senza1dio\SecurityShield\Health\HealthCheckInterface;

/**
 * Database Health Check
 *
 * Verifies database connection and optionally checks connection pool.
 */
class DatabaseHealthCheck implements HealthCheckInterface
{
    private \PDO $pdo;
    private ?int $maxConnections;
    private ?float $connectionWarningThreshold;

    /**
     * @param \PDO $pdo PDO connection
     * @param int|null $maxConnections Max connections for pool monitoring
     * @param float|null $connectionWarningThreshold Connection usage % for degraded
     */
    public function __construct(
        \PDO $pdo,
        ?int $maxConnections = null,
        ?float $connectionWarningThreshold = 80.0
    ) {
        $this->pdo = $pdo;
        $this->maxConnections = $maxConnections;
        $this->connectionWarningThreshold = $connectionWarningThreshold;
    }

    public function check(): CheckResult
    {
        try {
            // Basic connectivity check
            $stmt = $this->pdo->query('SELECT 1');

            if ($stmt === false) {
                return CheckResult::unhealthy('Database query failed');
            }

            $result = $stmt->fetch(\PDO::FETCH_COLUMN);

            if ($result != 1) {
                return CheckResult::unhealthy('Database returned unexpected result');
            }

            $metadata = $this->getMetadata();

            // Check connection pool if configured
            if ($this->maxConnections !== null && isset($metadata['active_connections'])) {
                $usage = ($metadata['active_connections'] / $this->maxConnections) * 100;
                $metadata['connection_usage_percent'] = round($usage, 2);

                if ($this->connectionWarningThreshold !== null && $usage >= $this->connectionWarningThreshold) {
                    return CheckResult::degraded(
                        "Connection pool usage high: {$usage}%",
                        $metadata
                    );
                }
            }

            return CheckResult::healthy('Connected', $metadata);

        } catch (\PDOException $e) {
            return CheckResult::unhealthy('Database connection failed: ' . $e->getMessage());
        } catch (\Throwable $e) {
            return CheckResult::unhealthy('Database check failed: ' . $e->getMessage());
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getMetadata(): array
    {
        $metadata = [];

        try {
            $driver = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
            $metadata['driver'] = $driver;
            $metadata['server_version'] = $this->pdo->getAttribute(\PDO::ATTR_SERVER_VERSION);

            // Get connection count (MySQL/MariaDB)
            if ($driver === 'mysql') {
                $stmt = $this->pdo->query("SHOW STATUS LIKE 'Threads_connected'");
                if ($stmt) {
                    $row = $stmt->fetch(\PDO::FETCH_ASSOC);
                    if ($row && isset($row['Value'])) {
                        $metadata['active_connections'] = (int) $row['Value'];
                    }
                }
            }

            // Get connection count (PostgreSQL)
            if ($driver === 'pgsql') {
                $stmt = $this->pdo->query("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'");
                if ($stmt) {
                    $metadata['active_connections'] = (int) $stmt->fetchColumn();
                }
            }

        } catch (\Throwable $e) {
            // Ignore metadata collection errors
        }

        return $metadata;
    }
}
