<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Config;

/**
 * Configuration Validation Result
 *
 * Immutable result object for configuration validation.
 *
 * @package Senza1dio\SecurityShield\Config
 */
final class ValidationResult
{
    public readonly bool $valid;
    public readonly ?string $error;

    private function __construct(bool $valid, ?string $error = null)
    {
        $this->valid = $valid;
        $this->error = $error;
    }

    /**
     * Create a valid result
     */
    public static function valid(): self
    {
        return new self(true, null);
    }

    /**
     * Create an invalid result with error message
     */
    public static function invalid(string $error): self
    {
        return new self(false, $error);
    }

    /**
     * Check if validation passed
     */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * Check if validation failed
     */
    public function isInvalid(): bool
    {
        return !$this->valid;
    }

    /**
     * Get error message (null if valid)
     */
    public function getError(): ?string
    {
        return $this->error;
    }

    /**
     * Throw exception if invalid
     *
     * @throws \InvalidArgumentException
     */
    public function orThrow(): void
    {
        if (!$this->valid) {
            throw new \InvalidArgumentException($this->error ?? 'Validation failed');
        }
    }

    /**
     * Execute callback if valid
     *
     * @param callable(): void $callback
     */
    public function ifValid(callable $callback): self
    {
        if ($this->valid) {
            $callback();
        }

        return $this;
    }

    /**
     * Execute callback if invalid
     *
     * @param callable(string $error): void $callback
     */
    public function ifInvalid(callable $callback): self
    {
        if (!$this->valid && $this->error !== null) {
            $callback($this->error);
        }

        return $this;
    }
}
