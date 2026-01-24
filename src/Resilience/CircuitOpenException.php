<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Exception thrown when attempting to use an open circuit
 *
 * Contains circuit statistics for debugging and monitoring.
 */
class CircuitOpenException extends \Exception
{
    private string $circuitName;

    /** @var array<string, mixed> */
    private array $statistics;

    /**
     * @param string $message Exception message
     * @param string $circuitName Name of the open circuit
     * @param array<string, mixed> $statistics Circuit statistics at time of exception
     */
    public function __construct(string $message, string $circuitName, array $statistics = [])
    {
        parent::__construct($message);
        $this->circuitName = $circuitName;
        $this->statistics = $statistics;
    }

    /**
     * Get the name of the circuit that was open
     */
    public function getCircuitName(): string
    {
        return $this->circuitName;
    }

    /**
     * Get circuit statistics at the time the exception was thrown
     *
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        return $this->statistics;
    }

    /**
     * Get time until the circuit will attempt recovery (seconds)
     */
    public function getTimeUntilRecovery(): ?int
    {
        return $this->statistics['time_until_recovery'] ?? null;
    }
}
