<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Exception thrown when bulkhead queue timeout is exceeded
 */
class BulkheadTimeoutException extends \Exception
{
    private string $bulkheadName;
    private float $timeout;

    public function __construct(string $message, string $bulkheadName, float $timeout)
    {
        parent::__construct($message);
        $this->bulkheadName = $bulkheadName;
        $this->timeout = $timeout;
    }

    public function getBulkheadName(): string
    {
        return $this->bulkheadName;
    }

    public function getTimeout(): float
    {
        return $this->timeout;
    }
}
