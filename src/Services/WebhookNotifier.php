<?php

namespace Senza1dio\SecurityShield\Services;

/**
 * Webhook Notifier
 *
 * Sends real-time alerts to webhook endpoints (Slack, Discord, custom)
 *
 * @package Senza1dio\SecurityShield\Services
 */
class WebhookNotifier
{
    /** @var array<string, string> Webhook URLs by name */
    private array $webhooks = [];

    private int $timeout = 3; // 3 seconds
    private bool $async = true; // Send async to not block requests

    /**
     * Add webhook endpoint
     *
     * @param string $name Webhook name (e.g., 'slack', 'discord', 'custom')
     * @param string $url Webhook URL
     * @return self
     */
    public function addWebhook(string $name, string $url): self
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Invalid webhook URL: {$url}");
        }

        // SECURITY: Require HTTPS to prevent credential interception
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if ($scheme !== 'https') {
            throw new \InvalidArgumentException("Webhook URL must use HTTPS: {$url}");
        }

        // SECURITY: Prevent SSRF by blocking private/local URLs
        $host = parse_url($url, PHP_URL_HOST);
        if (is_string($host)) {
            // Block localhost variants (IPv4 + IPv6)
            $hostLower = strtolower($host);
            if (in_array($hostLower, ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true)) {
                throw new \InvalidArgumentException("Webhook URL cannot be localhost: {$url}");
            }

            // Block private IP ranges using IPUtils (comprehensive check)
            if (filter_var($host, FILTER_VALIDATE_IP)) {
                if (\Senza1dio\SecurityShield\Utils\IPUtils::isPrivateIP($host)) {
                    throw new \InvalidArgumentException("Webhook URL cannot be private/reserved IP: {$url}");
                }
            }
        }

        $this->webhooks[$name] = $url;
        return $this;
    }

    /**
     * Send notification to all webhooks
     *
     * @param string $event Event type (e.g., 'ip_banned', 'honeypot_access', 'critical_attack')
     * @param array<string, mixed> $data Event data
     * @return void
     */
    public function notify(string $event, array $data): void
    {
        foreach ($this->webhooks as $name => $url) {
            $this->send($url, $event, $data);
        }
    }

    /**
     * Send to specific webhook
     *
     * @param string $url Webhook URL
     * @param string $event Event type
     * @param array<string, mixed> $data Event data
     * @return void
     */
    private function send(string $url, string $event, array $data): void
    {
        $payload = [
            'event' => $event,
            'timestamp' => time(),
            'data' => $data,
        ];

        $json = json_encode($payload);

        if ($json === false) {
            return; // JSON encoding failed
        }

        if ($this->async) {
            // Send async (non-blocking)
            $this->sendAsync($url, $json);
        } else {
            // Send sync (blocking)
            $this->sendSync($url, $json);
        }
    }

    /**
     * Send webhook async (fire-and-forget, non-blocking)
     *
     * IMPLEMENTATION NOTES:
     * This is NOT truly async (no promises/coroutines). It's "fire-and-forget":
     * - Opens socket connection
     * - Writes HTTP request
     * - Closes socket WITHOUT waiting for response
     * - Response is discarded by OS after TCP FIN
     *
     * TRADE-OFFS:
     * - PRO: Zero dependencies, works everywhere
     * - PRO: Doesn't block the request (~1-5ms overhead)
     * - CON: No delivery confirmation
     * - CON: No retry on failure
     * - CON: May fail silently if webhook endpoint is down
     *
     * FOR TRUE ASYNC:
     * - Use ReactPHP HttpClient
     * - Use Guzzle with promises
     * - Use job queue (Redis/RabbitMQ + worker)
     *
     * @param string $url
     * @param string $json
     * @return void
     */
    private function sendAsync(string $url, string $json): void
    {
        // Use fsockopen for non-blocking HTTP POST
        $parts = parse_url($url);

        if ($parts === false || !is_array($parts)) {
            return;
        }

        $scheme = $parts['scheme'] ?? 'http';
        $host = $parts['host'] ?? '';
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        $path = $parts['path'] ?? '/';

        // Preserve query string if present (e.g., Slack webhook tokens)
        if (isset($parts['query']) && $parts['query'] !== '') {
            $path .= '?' . $parts['query'];
        }

        if ($scheme === 'https') {
            $host = 'ssl://' . $host;
        }

        $fp = @fsockopen($host, $port, $errno, $errstr, 1);

        if (!$fp) {
            error_log("WebhookNotifier: Async connection failed to {$host}:{$port} - {$errstr} ({$errno})");
            return;
        }

        try {
            $hostHeader = $parts['host'] ?? '';

            // SECURITY: Prevent CRLF injection in Host header
            if (empty($hostHeader) || preg_match('/[\r\n]/', $hostHeader)) {
                error_log("WebhookNotifier: Invalid host header detected");
                return;
            }

            // SECURITY: Sanitize path to prevent request smuggling
            $safePath = preg_replace('/[\r\n]/', '', $path);

            $request = "POST {$safePath} HTTP/1.1\r\n";
            $request .= "Host: {$hostHeader}\r\n";
            $request .= "Content-Type: application/json\r\n";
            $request .= "Content-Length: " . strlen($json) . "\r\n";
            $request .= "Connection: Close\r\n\r\n";
            $request .= $json;

            // Set write timeout
            stream_set_timeout($fp, 5);

            $written = fwrite($fp, $request);
            if ($written === false) {
                error_log("WebhookNotifier: Failed to write to socket");
            }
        } finally {
            @fclose($fp);
        }
    }

    /**
     * Send webhook sync (blocking)
     *
     * @param string $url
     * @param string $json
     * @return void
     */
    private function sendSync(string $url, string $json): void
    {
        try {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $json,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            ]);

            curl_exec($ch);
            // PHP 8.0+ automatically closes CurlHandle when going out of scope
            // For PHP 7.x compatibility, we must explicitly close
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
        } catch (\Throwable $e) {
            // Graceful degradation - don't crash on webhook failure
        }
    }

    /**
     * Set timeout for webhook requests
     *
     * @param int $seconds Timeout in seconds
     * @return self
     */
    public function setTimeout(int $seconds): self
    {
        $this->timeout = $seconds;
        return $this;
    }

    /**
     * Enable/disable async mode
     *
     * @param bool $async
     * @return self
     */
    public function setAsync(bool $async): self
    {
        $this->async = $async;
        return $this;
    }
}
