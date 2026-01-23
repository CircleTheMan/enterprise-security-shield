<?php

namespace Senza1dio\SecurityShield\Contracts;

/**
 * Logger Interface - PSR-3-like (NOT PSR-3)
 *
 * IMPORTANT: This interface does NOT extend Psr\Log\LoggerInterface.
 * It's PSR-3-*like* (same method names, signatures), but technically NOT PSR-3 compliant.
 *
 * WHY NOT EXTEND PSR-3:
 * - Zero external dependencies (package is dependency-free)
 * - Allows integration with any logging system without requiring psr/log package
 * - Users can wrap their PSR-3 logger with this interface trivially
 *
 * INTEGRATION:
 * - Monolog: Implements PSR-3 natively, can be wrapped or directly used
 * - Laravel Log: Implements PSR-3 natively, can be wrapped or directly used
 * - Symfony Logger: Implements PSR-3 natively, can be wrapped or directly used
 * - Custom loggers: Implement these 6 methods
 *
 * MISSING FROM PSR-3:
 * - log($level, $message, $context) method (generic log method)
 * - alert() and notice() methods (we use emergency/critical/warning instead)
 */
interface LoggerInterface
{
    /**
     * Log emergency event (system unusable)
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function emergency(string $message, array $context = []): void;

    /**
     * Log critical event (requires immediate action)
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function critical(string $message, array $context = []): void;

    /**
     * Log error event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function error(string $message, array $context = []): void;

    /**
     * Log warning event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function warning(string $message, array $context = []): void;

    /**
     * Log info event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function info(string $message, array $context = []): void;

    /**
     * Log debug event
     *
     * @param string $message
     * @param array<string, mixed> $context
     * @return void
     */
    public function debug(string $message, array $context = []): void;
}
