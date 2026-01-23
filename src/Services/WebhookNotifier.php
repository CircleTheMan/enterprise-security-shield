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

        // SECURITY: Prevent SSRF by blocking private/local URLs
        $host = parse_url($url, PHP_URL_HOST);
        if (is_string($host)) {
            // Block localhost variants (IPv4 + IPv6)
            if (in_array(strtolower($host), ['localhost', '127.0.0.1', '::1'], true)) {
                throw new \InvalidArgumentException("Webhook URL cannot be localhost: {$url}");
            }

            // Block private IP ranges (RFC 1918 for IPv4, RFC 4193 for IPv6)
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                // IPv4 private ranges
                $ip = ip2long($host);
                if ($ip !== false) {
                    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    if (($ip >= 167772160 && $ip <= 184549375) ||  // 10.0.0.0/8
                        ($ip >= 2886729728 && $ip <= 2887778303) || // 172.16.0.0/12
                        ($ip >= 3232235520 && $ip <= 3232301055)) { // 192.168.0.0/16
                        throw new \InvalidArgumentException("Webhook URL cannot be private IP: {$url}");
                    }
                }
            } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                // IPv6 private/local ranges (RFC 4193: fc00::/7, fe80::/10, ::1)
                $ipBin = inet_pton($host);
                if ($ipBin !== false) {
                    $firstByte = ord($ipBin[0]);
                    // fc00::/7 (private), fe80::/10 (link-local)
                    if (($firstByte >= 0xfc && $firstByte <= 0xfd) || // fc00::/7
                        ($firstByte == 0xfe && (ord($ipBin[1]) & 0xc0) == 0x80)) { // fe80::/10
                        throw new \InvalidArgumentException("Webhook URL cannot be private IPv6: {$url}");
                    }
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
     * Send webhook async (non-blocking)
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

        if ($scheme === 'https') {
            $host = 'ssl://' . $host;
        }

        $fp = @fsockopen($host, $port, $errno, $errstr, 1);

        if ($fp) {
            $hostHeader = $parts['host'] ?? $host;
            $request = "POST {$path} HTTP/1.1\r\n";
            $request .= "Host: {$hostHeader}\r\n";
            $request .= "Content-Type: application/json\r\n";
            $request .= "Content-Length: " . strlen($json) . "\r\n";
            $request .= "Connection: Close\r\n\r\n";
            $request .= $json;

            fwrite($fp, $request);
            fclose($fp);
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
            curl_close($ch);
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
