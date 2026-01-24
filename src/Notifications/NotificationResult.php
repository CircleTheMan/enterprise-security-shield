<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Notification Result
 *
 * Contains results of a notification dispatch.
 *
 * @package Senza1dio\SecurityShield\Notifications
 */
class NotificationResult
{
    /** @var array<string, bool> */
    private array $results;

    /** @var array<string, string> */
    private array $errors;

    /**
     * @param array<string, bool> $results Channel results (name => success)
     * @param array<string, string> $errors Channel errors (name => error message)
     */
    public function __construct(array $results, array $errors = [])
    {
        $this->results = $results;
        $this->errors = $errors;
    }

    /**
     * Check if all notifications were successful
     */
    public function allSuccessful(): bool
    {
        if (empty($this->results)) {
            return false;
        }

        return !in_array(false, $this->results, true);
    }

    /**
     * Check if at least one notification was successful
     */
    public function anySuccessful(): bool
    {
        return in_array(true, $this->results, true);
    }

    /**
     * Check if all notifications failed
     */
    public function allFailed(): bool
    {
        if (empty($this->results)) {
            return true;
        }

        return !in_array(true, $this->results, true);
    }

    /**
     * Get success count
     */
    public function successCount(): int
    {
        return count(array_filter($this->results));
    }

    /**
     * Get failure count
     */
    public function failureCount(): int
    {
        return count($this->results) - $this->successCount();
    }

    /**
     * Get successful channel names
     *
     * @return array<string>
     */
    public function getSuccessful(): array
    {
        return array_keys(array_filter($this->results));
    }

    /**
     * Get failed channel names
     *
     * @return array<string>
     */
    public function getFailed(): array
    {
        return array_keys(array_filter($this->results, fn($v) => $v === false));
    }

    /**
     * Get all results
     *
     * @return array<string, bool>
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Get all errors
     *
     * @return array<string, string>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Get error for a specific channel
     *
     * @param string $channel Channel name
     * @return string|null
     */
    public function getError(string $channel): ?string
    {
        return $this->errors[$channel] ?? null;
    }

    /**
     * Check if specific channel was successful
     *
     * @param string $channel Channel name
     * @return bool|null Null if channel not in results
     */
    public function wasSuccessful(string $channel): ?bool
    {
        return $this->results[$channel] ?? null;
    }

    /**
     * Export to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'all_successful' => $this->allSuccessful(),
            'any_successful' => $this->anySuccessful(),
            'success_count' => $this->successCount(),
            'failure_count' => $this->failureCount(),
            'results' => $this->results,
            'errors' => $this->errors,
        ];
    }
}
