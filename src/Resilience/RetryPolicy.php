<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Resilience;

/**
 * Retry Policy with Multiple Strategies
 *
 * Provides configurable retry behavior for transient failures.
 *
 * STRATEGIES:
 * - Exponential Backoff: 1s, 2s, 4s, 8s... (doubles each time)
 * - Exponential with Jitter: Adds randomness to prevent thundering herd
 * - Linear Backoff: 1s, 2s, 3s, 4s... (constant increment)
 * - Constant: Same delay each time
 * - Immediate: No delay (for testing or specific use cases)
 *
 * USAGE:
 * ```php
 * $policy = RetryPolicy::exponentialBackoff(3, 1.0, 30.0);
 *
 * $result = $policy->execute(function() {
 *     return $this->riskyOperation();
 * });
 *
 * // With exception filter
 * $policy = RetryPolicy::exponentialBackoff(3)
 *     ->retryOn(ConnectionException::class)
 *     ->retryOn(TimeoutException::class)
 *     ->doNotRetryOn(ValidationException::class);
 * ```
 *
 * @package Senza1dio\SecurityShield\Resilience
 */
class RetryPolicy
{
    private int $maxAttempts;
    private float $baseDelay;
    private float $maxDelay;
    private string $strategy;
    private float $multiplier;
    private float $jitterFactor;

    /** @var array<class-string<\Throwable>> */
    private array $retryableExceptions = [];

    /** @var array<class-string<\Throwable>> */
    private array $nonRetryableExceptions = [];

    /** @var array<callable(\Throwable): bool> */
    private array $retryPredicates = [];

    /** @var callable|null */
    private $onRetry = null;

    private const STRATEGY_EXPONENTIAL = 'exponential';
    private const STRATEGY_EXPONENTIAL_JITTER = 'exponential_jitter';
    private const STRATEGY_LINEAR = 'linear';
    private const STRATEGY_CONSTANT = 'constant';
    private const STRATEGY_IMMEDIATE = 'immediate';

    private function __construct(
        int $maxAttempts,
        float $baseDelay,
        float $maxDelay,
        string $strategy,
        float $multiplier = 2.0,
        float $jitterFactor = 0.5
    ) {
        $this->maxAttempts = max(1, $maxAttempts);
        $this->baseDelay = max(0, $baseDelay);
        $this->maxDelay = max($baseDelay, $maxDelay);
        $this->strategy = $strategy;
        $this->multiplier = max(1.0, $multiplier);
        $this->jitterFactor = min(1.0, max(0, $jitterFactor));
    }

    // ==================== FACTORY METHODS ====================

    /**
     * Create exponential backoff policy
     *
     * Delay doubles with each attempt: base, base*2, base*4, base*8...
     *
     * @param int $maxAttempts Maximum number of attempts (including first)
     * @param float $baseDelay Initial delay in seconds
     * @param float $maxDelay Maximum delay cap in seconds
     * @param float $multiplier Backoff multiplier (default 2.0)
     */
    public static function exponentialBackoff(
        int $maxAttempts = 3,
        float $baseDelay = 1.0,
        float $maxDelay = 30.0,
        float $multiplier = 2.0
    ): self {
        return new self($maxAttempts, $baseDelay, $maxDelay, self::STRATEGY_EXPONENTIAL, $multiplier);
    }

    /**
     * Create exponential backoff with jitter
     *
     * Like exponential, but adds randomness to prevent thundering herd problem.
     * Jitter range: delay * (1 - jitter) to delay * (1 + jitter)
     *
     * @param int $maxAttempts Maximum number of attempts
     * @param float $baseDelay Initial delay in seconds
     * @param float $maxDelay Maximum delay cap in seconds
     * @param float $jitterFactor Jitter factor 0.0-1.0 (default 0.5 = ±50%)
     */
    public static function exponentialBackoffWithJitter(
        int $maxAttempts = 3,
        float $baseDelay = 1.0,
        float $maxDelay = 30.0,
        float $jitterFactor = 0.5
    ): self {
        return new self($maxAttempts, $baseDelay, $maxDelay, self::STRATEGY_EXPONENTIAL_JITTER, 2.0, $jitterFactor);
    }

    /**
     * Create linear backoff policy
     *
     * Delay increases linearly: base, base*2, base*3, base*4...
     *
     * @param int $maxAttempts Maximum number of attempts
     * @param float $baseDelay Delay increment in seconds
     * @param float $maxDelay Maximum delay cap in seconds
     */
    public static function linearBackoff(
        int $maxAttempts = 3,
        float $baseDelay = 1.0,
        float $maxDelay = 30.0
    ): self {
        return new self($maxAttempts, $baseDelay, $maxDelay, self::STRATEGY_LINEAR);
    }

    /**
     * Create constant delay policy
     *
     * Same delay between each attempt.
     *
     * @param int $maxAttempts Maximum number of attempts
     * @param float $delay Constant delay in seconds
     */
    public static function constantDelay(int $maxAttempts = 3, float $delay = 1.0): self
    {
        return new self($maxAttempts, $delay, $delay, self::STRATEGY_CONSTANT);
    }

    /**
     * Create immediate retry policy (no delay)
     *
     * Use sparingly - only for idempotent operations where delay doesn't help.
     *
     * @param int $maxAttempts Maximum number of attempts
     */
    public static function immediate(int $maxAttempts = 3): self
    {
        return new self($maxAttempts, 0, 0, self::STRATEGY_IMMEDIATE);
    }

    /**
     * Create no-retry policy (fail immediately)
     */
    public static function noRetry(): self
    {
        return new self(1, 0, 0, self::STRATEGY_IMMEDIATE);
    }

    // ==================== CONFIGURATION ====================

    /**
     * Only retry on specific exception types
     *
     * @param class-string<\Throwable> $exceptionClass
     */
    public function retryOn(string $exceptionClass): self
    {
        $this->retryableExceptions[] = $exceptionClass;
        return $this;
    }

    /**
     * Never retry on specific exception types
     *
     * @param class-string<\Throwable> $exceptionClass
     */
    public function doNotRetryOn(string $exceptionClass): self
    {
        $this->nonRetryableExceptions[] = $exceptionClass;
        return $this;
    }

    /**
     * Add custom retry predicate
     *
     * @param callable(\Throwable): bool $predicate Returns true if should retry
     */
    public function retryIf(callable $predicate): self
    {
        $this->retryPredicates[] = $predicate;
        return $this;
    }

    /**
     * Register callback for retry events
     *
     * @param callable(\Throwable $e, int $attempt, float $delay): void $callback
     */
    public function onRetry(callable $callback): self
    {
        $this->onRetry = $callback;
        return $this;
    }

    // ==================== EXECUTION ====================

    /**
     * Execute operation with retry policy
     *
     * @template T
     * @param callable(): T $operation Operation to execute
     * @return T Result of successful operation
     * @throws \Throwable Last exception if all retries exhausted
     */
    public function execute(callable $operation): mixed
    {
        $lastException = null;

        for ($attempt = 1; $attempt <= $this->maxAttempts; $attempt++) {
            try {
                return $operation();
            } catch (\Throwable $e) {
                $lastException = $e;

                // Check if we should retry
                if (!$this->shouldRetry($e, $attempt)) {
                    throw $e;
                }

                // Calculate and apply delay
                if ($attempt < $this->maxAttempts) {
                    $delay = $this->calculateDelay($attempt);

                    // Emit retry event
                    if ($this->onRetry !== null) {
                        ($this->onRetry)($e, $attempt, $delay);
                    }

                    // Sleep (microseconds for precision)
                    if ($delay > 0) {
                        usleep((int) ($delay * 1_000_000));
                    }
                }
            }
        }

        // All retries exhausted
        throw $lastException ?? new \RuntimeException('Retry policy exhausted with no exception');
    }

    /**
     * Execute async operation with retry policy
     *
     * Returns a callable that can be used with async libraries.
     *
     * @template T
     * @param callable(): T $operation
     * @return callable(): T
     */
    public function wrapAsync(callable $operation): callable
    {
        return fn() => $this->execute($operation);
    }

    // ==================== PRIVATE METHODS ====================

    private function shouldRetry(\Throwable $e, int $attempt): bool
    {
        // No more attempts left
        if ($attempt >= $this->maxAttempts) {
            return false;
        }

        // Check non-retryable exceptions first
        foreach ($this->nonRetryableExceptions as $exceptionClass) {
            if ($e instanceof $exceptionClass) {
                return false;
            }
        }

        // If retryable exceptions specified, check if this is one
        if (!empty($this->retryableExceptions)) {
            $isRetryable = false;
            foreach ($this->retryableExceptions as $exceptionClass) {
                if ($e instanceof $exceptionClass) {
                    $isRetryable = true;
                    break;
                }
            }
            if (!$isRetryable) {
                return false;
            }
        }

        // Check custom predicates
        foreach ($this->retryPredicates as $predicate) {
            if (!$predicate($e)) {
                return false;
            }
        }

        return true;
    }

    private function calculateDelay(int $attempt): float
    {
        $delay = match ($this->strategy) {
            self::STRATEGY_EXPONENTIAL => $this->baseDelay * pow($this->multiplier, $attempt - 1),
            self::STRATEGY_EXPONENTIAL_JITTER => $this->addJitter(
                $this->baseDelay * pow($this->multiplier, $attempt - 1)
            ),
            self::STRATEGY_LINEAR => $this->baseDelay * $attempt,
            self::STRATEGY_CONSTANT => $this->baseDelay,
            self::STRATEGY_IMMEDIATE => 0,
            default => $this->baseDelay,
        };

        return min($delay, $this->maxDelay);
    }

    private function addJitter(float $delay): float
    {
        $jitterRange = $delay * $this->jitterFactor;
        $jitter = (mt_rand() / mt_getrandmax()) * 2 * $jitterRange - $jitterRange;
        return max(0, $delay + $jitter);
    }

    /**
     * Get policy configuration for debugging
     *
     * @return array<string, mixed>
     */
    public function getConfiguration(): array
    {
        return [
            'max_attempts' => $this->maxAttempts,
            'base_delay' => $this->baseDelay,
            'max_delay' => $this->maxDelay,
            'strategy' => $this->strategy,
            'multiplier' => $this->multiplier,
            'jitter_factor' => $this->jitterFactor,
            'retryable_exceptions' => $this->retryableExceptions,
            'non_retryable_exceptions' => $this->nonRetryableExceptions,
        ];
    }
}
