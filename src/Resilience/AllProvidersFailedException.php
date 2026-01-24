<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Exception thrown when all providers in a fallback chain fail
 */
class AllProvidersFailedException extends \Exception
{
    /** @var array<string, \Throwable> */
    private array $providerErrors;

    /**
     * @param string $message Exception message
     * @param array<string, \Throwable> $providerErrors Map of provider name to exception
     */
    public function __construct(string $message, array $providerErrors = [])
    {
        parent::__construct($message);
        $this->providerErrors = $providerErrors;
    }

    /**
     * Get all provider errors
     *
     * @return array<string, \Throwable>
     */
    public function getProviderErrors(): array
    {
        return $this->providerErrors;
    }

    /**
     * Get error for specific provider
     */
    public function getErrorForProvider(string $name): ?\Throwable
    {
        return $this->providerErrors[$name] ?? null;
    }

    /**
     * Get all provider names that failed
     *
     * @return array<string>
     */
    public function getFailedProviders(): array
    {
        return array_keys($this->providerErrors);
    }

    /**
     * Get summary of all errors
     *
     * @return array<string, string>
     */
    public function getErrorSummary(): array
    {
        return array_map(fn($e) => $e->getMessage(), $this->providerErrors);
    }
}
