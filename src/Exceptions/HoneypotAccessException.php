<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Exceptions;

/**
 * Honeypot Access Exception
 *
 * Thrown when a request matches a honeypot path.
 * Contains the fake response to send to the attacker.
 *
 * USAGE IN BOOTSTRAP:
 * ```php
 * try {
 *     $honeypot->handle($_SERVER);
 * } catch (HoneypotAccessException $e) {
 *     // Send fake response
 *     if (!headers_sent()) {
 *         echo $e->getResponse();
 *     }
 *     // Optionally exit or return (framework-dependent)
 *     // exit; // PHP-FPM
 *     // return; // Swoole/RoadRunner
 * }
 * ```
 *
 * WHY EXCEPTION INSTEAD OF exit():
 * - Works with long-running processes (Swoole, RoadRunner, ReactPHP)
 * - Testable with PHPUnit (no exit during tests)
 * - Allows cleanup handlers to run (fastcgi_finish_request)
 * - Framework-agnostic response handling
 */
class HoneypotAccessException extends \Exception
{
    private string $response;
    private string $clientIp;
    private string $path;

    /**
     * @param string $response Fake response to send to attacker
     * @param string $clientIp Attacker's IP address
     * @param string $path Honeypot path that was accessed
     */
    public function __construct(string $response, string $clientIp = '', string $path = '')
    {
        parent::__construct("Honeypot access detected from {$clientIp} on {$path}");
        $this->response = $response;
        $this->clientIp = $clientIp;
        $this->path = $path;
    }

    /**
     * Get the fake response to send to the attacker
     */
    public function getResponse(): string
    {
        return $this->response;
    }

    /**
     * Get the attacker's IP address
     */
    public function getClientIp(): string
    {
        return $this->clientIp;
    }

    /**
     * Get the honeypot path that was accessed
     */
    public function getPath(): string
    {
        return $this->path;
    }
}
