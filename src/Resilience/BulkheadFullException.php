<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Exception thrown when bulkhead is at capacity
 */
class BulkheadFullException extends \Exception
{
    private string $bulkheadName;

    /** @var array<string, mixed> */
    private array $statistics;

    /**
     * @param string $message Exception message
     * @param string $bulkheadName Name of the full bulkhead
     * @param array<string, mixed> $statistics Bulkhead statistics
     */
    public function __construct(string $message, string $bulkheadName, array $statistics = [])
    {
        parent::__construct($message);
        $this->bulkheadName = $bulkheadName;
        $this->statistics = $statistics;
    }

    public function getBulkheadName(): string
    {
        return $this->bulkheadName;
    }

    /**
     * @return array<string, mixed>
     */
    public function getStatistics(): array
    {
        return $this->statistics;
    }
}
