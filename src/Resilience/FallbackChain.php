<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Fallback Chain Pattern Implementation.
 *
 * Tries multiple providers/operations in sequence until one succeeds.
 *
 * USAGE:
 * ```php
 * $chain = new FallbackChain();
 *
 * $chain
 *     ->add('redis', fn() => $redis->get($key))
 *     ->add('database', fn() => $db->get($key))
 *     ->add('default', fn() => null);
 *
 * $result = $chain->execute();
 * echo $chain->getUsedProvider(); // 'redis', 'database', or 'default'
 * ```
 *
 * WITH CIRCUIT BREAKERS:
 * ```php
 * $chain = new FallbackChain();
 *
 * $chain
 *     ->addWithCircuitBreaker('redis', $redisBreaker, fn() => $redis->get($key))
 *     ->addWithCircuitBreaker('database', $dbBreaker, fn() => $db->get($key))
 *     ->add('default', fn() => null);
 * ```
 */
class FallbackChain
{
    /** @var array<array{name: string, operation: callable, circuit_breaker: CircuitBreaker|null}> */
    private array $providers = [];

    private ?string $usedProvider = null;

    private ?string $lastError = null;

    /** @var array<string, \Throwable> */
    private array $errors = [];

    /** @var callable|null */
    private $onFallback = null;

    /**
     * Add a provider to the chain.
     *
     * @param string $name Provider identifier
     * @param callable(): mixed $operation Operation to execute
     */
    public function add(string $name, callable $operation): self
    {
        $this->providers[] = [
            'name' => $name,
            'operation' => $operation,
            'circuit_breaker' => null,
        ];

        return $this;
    }

    /**
     * Add a provider with circuit breaker protection.
     *
     * If circuit is open, provider is skipped without trying.
     *
     * @param string $name Provider identifier
     * @param CircuitBreaker $circuitBreaker Circuit breaker for this provider
     * @param callable(): mixed $operation Operation to execute
     */
    public function addWithCircuitBreaker(
        string $name,
        CircuitBreaker $circuitBreaker,
        callable $operation,
    ): self {
        $this->providers[] = [
            'name' => $name,
            'operation' => $operation,
            'circuit_breaker' => $circuitBreaker,
        ];

        return $this;
    }

    /**
     * Register callback for fallback events.
     *
     * @param callable(string $failedProvider, string $nextProvider, \Throwable $error): void $callback
     */
    public function onFallback(callable $callback): self
    {
        $this->onFallback = $callback;

        return $this;
    }

    /**
     * Execute the fallback chain.
     *
     * @throws AllProvidersFailedException When all providers fail and no default provided
     *
     * @return mixed Result from first successful provider, or null if all failed
     */
    public function execute(): mixed
    {
        $this->usedProvider = null;
        $this->lastError = null;
        $this->errors = [];

        foreach ($this->providers as $index => $provider) {
            $name = $provider['name'];
            $operation = $provider['operation'];
            $circuitBreaker = $provider['circuit_breaker'];

            try {
                // Check circuit breaker
                if ($circuitBreaker !== null && !$circuitBreaker->isAvailable()) {
                    $this->errors[$name] = new CircuitOpenException(
                        "Circuit for '{$name}' is open",
                        $name,
                    );
                    continue;
                }

                // Execute with or without circuit breaker
                if ($circuitBreaker !== null) {
                    $result = $circuitBreaker->call($operation);
                } else {
                    $result = $operation();
                }

                $this->usedProvider = $name;

                return $result;

            } catch (\Throwable $e) {
                $this->errors[$name] = $e;
                $this->lastError = $e->getMessage();

                // Emit fallback event
                if ($this->onFallback !== null && isset($this->providers[$index + 1])) {
                    $nextProvider = $this->providers[$index + 1]['name'];
                    ($this->onFallback)($name, $nextProvider, $e);
                }
            }
        }

        // All providers failed
        throw new AllProvidersFailedException(
            'All providers in fallback chain failed',
            $this->errors,
        );
    }

    /**
     * Execute with a final default value.
     *
     * @template T
     *
     * @param T $default Value to return if all providers fail
     *
     * @return T Result from successful provider or default
     */
    public function executeWithDefault(mixed $default): mixed
    {
        try {
            return $this->execute();
        } catch (AllProvidersFailedException $e) {
            $this->usedProvider = 'default';

            return $default;
        }
    }

    /**
     * Get the name of the provider that was used.
     */
    public function getUsedProvider(): ?string
    {
        return $this->usedProvider;
    }

    /**
     * Get the last error message.
     */
    public function getLastError(): ?string
    {
        return $this->lastError;
    }

    /**
     * Get all errors that occurred.
     *
     * @return array<string, \Throwable>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Check if a fallback was used.
     */
    public function didFallback(): bool
    {
        if ($this->usedProvider === null) {
            return false;
        }

        // Check if the used provider was the first one
        if (empty($this->providers)) {
            return false;
        }

        return $this->providers[0]['name'] !== $this->usedProvider;
    }

    /**
     * Get chain statistics.
     *
     * @return array{
     *     providers: array<string>,
     *     used_provider: string|null,
     *     did_fallback: bool,
     *     errors: array<string, string>
     * }
     */
    public function getStatistics(): array
    {
        return [
            'providers' => array_column($this->providers, 'name'),
            'used_provider' => $this->usedProvider,
            'did_fallback' => $this->didFallback(),
            'errors' => array_map(fn ($e) => $e->getMessage(), $this->errors),
        ];
    }

    /**
     * Clear the chain for reuse.
     */
    public function clear(): self
    {
        $this->providers = [];
        $this->usedProvider = null;
        $this->lastError = null;
        $this->errors = [];

        return $this;
    }
}
