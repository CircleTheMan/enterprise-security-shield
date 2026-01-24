<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Slack Notifier
 *
 * Sends notifications via Slack Incoming Webhooks.
 *
 * SETUP:
 * 1. Go to https://api.slack.com/apps
 * 2. Create new app → From scratch
 * 3. Add "Incoming Webhooks" feature
 * 4. Create webhook for your channel
 * 5. Copy the webhook URL
 *
 * USAGE:
 * ```php
 * $slack = new SlackNotifier('https://hooks.slack.com/services/XXX/YYY/ZZZ');
 *
 * // Simple message
 * $slack->send('Server is under attack!');
 *
 * // Alert with details
 * $slack->alert('🚨 Security Alert', 'IP banned: 1.2.3.4', [
 *     'reason' => 'Honeypot access',
 *     'score' => 100,
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Notifications
 */
class SlackNotifier implements NotifierInterface
{
    private string $webhookUrl;
    private int $timeout;
    private ?string $channel;
    private ?string $username;
    private ?string $iconEmoji;

    /**
     * @param string $webhookUrl Slack webhook URL
     * @param int $timeout Request timeout in seconds
     * @param string|null $channel Override default channel
     * @param string|null $username Override bot username
     * @param string|null $iconEmoji Override bot icon emoji
     */
    public function __construct(
        string $webhookUrl,
        int $timeout = 10,
        ?string $channel = null,
        ?string $username = 'Security Shield',
        ?string $iconEmoji = ':shield:'
    ) {
        $this->webhookUrl = $webhookUrl;
        $this->timeout = $timeout;
        $this->channel = $channel;
        $this->username = $username;
        $this->iconEmoji = $iconEmoji;
    }

    public function getName(): string
    {
        return 'slack';
    }

    public function isConfigured(): bool
    {
        return !empty($this->webhookUrl) &&
               str_starts_with($this->webhookUrl, 'https://hooks.slack.com/');
    }

    public function send(string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload($message);

        if (!empty($context)) {
            $payload['attachments'] = [
                $this->buildContextAttachment($context),
            ];
        }

        return $this->request($payload);
    }

    public function alert(string $title, string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload('');

        $attachment = [
            'color' => 'danger',
            'title' => $title,
            'text' => $message,
            'ts' => time(),
        ];

        if (!empty($context)) {
            $attachment['fields'] = $this->buildFields($context);
        }

        $payload['attachments'] = [$attachment];

        return $this->request($payload);
    }

    /**
     * Send message with custom blocks (Slack Block Kit)
     *
     * @param array<int, array<string, mixed>> $blocks Slack blocks
     * @param string|null $fallbackText Fallback text for notifications
     * @return bool
     */
    public function sendBlocks(array $blocks, ?string $fallbackText = null): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload($fallbackText ?? 'New notification');
        $payload['blocks'] = $blocks;

        return $this->request($payload);
    }

    /**
     * Send with custom color attachment
     *
     * @param string $message Message text
     * @param string $color Color (good, warning, danger, or hex)
     * @param array<string, mixed> $context Additional fields
     * @return bool
     */
    public function sendWithColor(string $message, string $color, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload('');

        $attachment = [
            'color' => $color,
            'text' => $message,
            'ts' => time(),
        ];

        if (!empty($context)) {
            $attachment['fields'] = $this->buildFields($context);
        }

        $payload['attachments'] = [$attachment];

        return $this->request($payload);
    }

    /**
     * Build base payload
     *
     * @param string $text Message text
     * @return array<string, mixed>
     */
    private function buildPayload(string $text): array
    {
        $payload = ['text' => $text];

        if ($this->channel !== null) {
            $payload['channel'] = $this->channel;
        }

        if ($this->username !== null) {
            $payload['username'] = $this->username;
        }

        if ($this->iconEmoji !== null) {
            $payload['icon_emoji'] = $this->iconEmoji;
        }

        return $payload;
    }

    /**
     * Build context attachment
     *
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function buildContextAttachment(array $context): array
    {
        return [
            'color' => '#36a64f',
            'fields' => $this->buildFields($context),
            'ts' => time(),
        ];
    }

    /**
     * Build attachment fields from context
     *
     * @param array<string, mixed> $context
     * @return array<int, array{title: string, value: string, short: bool}>
     */
    private function buildFields(array $context): array
    {
        $fields = [];

        foreach ($context as $key => $value) {
            $formattedValue = is_array($value)
                ? '```' . json_encode($value, JSON_PRETTY_PRINT) . '```'
                : (string) $value;

            $fields[] = [
                'title' => ucfirst(str_replace('_', ' ', $key)),
                'value' => $formattedValue,
                'short' => strlen($formattedValue) < 40,
            ];
        }

        return $fields;
    }

    /**
     * Make HTTP request to Slack
     *
     * @param array<string, mixed> $payload
     * @return bool
     */
    private function request(array $payload): bool
    {
        try {
            $json = json_encode($payload);

            if ($json === false) {
                return false;
            }

            $ch = curl_init();

            curl_setopt_array($ch, [
                CURLOPT_URL => $this->webhookUrl,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $json,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                ],
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            return $response === 'ok' || $httpCode === 200;

        } catch (\Throwable $e) {
            return false;
        }
    }
}
