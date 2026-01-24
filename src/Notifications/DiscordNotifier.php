<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Discord Notifier
 *
 * Sends notifications via Discord Webhooks.
 *
 * SETUP:
 * 1. Go to your Discord server
 * 2. Server Settings → Integrations → Webhooks
 * 3. New Webhook → Copy Webhook URL
 *
 * USAGE:
 * ```php
 * $discord = new DiscordNotifier('https://discord.com/api/webhooks/XXX/YYY');
 *
 * // Simple message
 * $discord->send('Server is under attack!');
 *
 * // Alert with embed
 * $discord->alert('🚨 Security Alert', 'IP banned: 1.2.3.4', [
 *     'reason' => 'Honeypot access',
 *     'score' => 100,
 * ]);
 * ```
 *
 * @package Senza1dio\SecurityShield\Notifications
 */
class DiscordNotifier implements NotifierInterface
{
    private string $webhookUrl;
    private int $timeout;
    private ?string $username;
    private ?string $avatarUrl;

    /**
     * @param string $webhookUrl Discord webhook URL
     * @param int $timeout Request timeout in seconds
     * @param string|null $username Override bot username
     * @param string|null $avatarUrl Override bot avatar URL
     */
    public function __construct(
        string $webhookUrl,
        int $timeout = 10,
        ?string $username = 'Security Shield',
        ?string $avatarUrl = null
    ) {
        $this->webhookUrl = $webhookUrl;
        $this->timeout = $timeout;
        $this->username = $username;
        $this->avatarUrl = $avatarUrl;
    }

    public function getName(): string
    {
        return 'discord';
    }

    public function isConfigured(): bool
    {
        return !empty($this->webhookUrl) &&
               str_starts_with($this->webhookUrl, 'https://discord.com/api/webhooks/');
    }

    public function send(string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload($message);

        if (!empty($context)) {
            $payload['embeds'] = [
                $this->buildEmbed('Details', '', $context, 0x3498db), // Blue
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
        $payload['embeds'] = [
            $this->buildEmbed($title, $message, $context, 0xe74c3c), // Red
        ];

        return $this->request($payload);
    }

    /**
     * Send with custom embed
     *
     * @param string $title Embed title
     * @param string $description Embed description
     * @param int $color Embed color (hex)
     * @param array<string, mixed> $fields Embed fields
     * @param string|null $thumbnailUrl Thumbnail image URL
     * @param string|null $imageUrl Main image URL
     * @return bool
     */
    public function sendEmbed(
        string $title,
        string $description,
        int $color = 0x3498db,
        array $fields = [],
        ?string $thumbnailUrl = null,
        ?string $imageUrl = null
    ): bool {
        if (!$this->isConfigured()) {
            return false;
        }

        $embed = $this->buildEmbed($title, $description, $fields, $color);

        if ($thumbnailUrl !== null) {
            $embed['thumbnail'] = ['url' => $thumbnailUrl];
        }

        if ($imageUrl !== null) {
            $embed['image'] = ['url' => $imageUrl];
        }

        $payload = $this->buildPayload('');
        $payload['embeds'] = [$embed];

        return $this->request($payload);
    }

    /**
     * Send success notification (green)
     *
     * @param string $title Title
     * @param string $message Message
     * @param array<string, mixed> $context Context
     * @return bool
     */
    public function success(string $title, string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload('');
        $payload['embeds'] = [
            $this->buildEmbed("✅ {$title}", $message, $context, 0x2ecc71), // Green
        ];

        return $this->request($payload);
    }

    /**
     * Send warning notification (yellow)
     *
     * @param string $title Title
     * @param string $message Message
     * @param array<string, mixed> $context Context
     * @return bool
     */
    public function warning(string $title, string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $payload = $this->buildPayload('');
        $payload['embeds'] = [
            $this->buildEmbed("⚠️ {$title}", $message, $context, 0xf39c12), // Yellow
        ];

        return $this->request($payload);
    }

    /**
     * Build base payload
     *
     * @param string $content Message content
     * @return array<string, mixed>
     */
    private function buildPayload(string $content): array
    {
        $payload = [];

        if ($content !== '') {
            $payload['content'] = $content;
        }

        if ($this->username !== null) {
            $payload['username'] = $this->username;
        }

        if ($this->avatarUrl !== null) {
            $payload['avatar_url'] = $this->avatarUrl;
        }

        return $payload;
    }

    /**
     * Build Discord embed
     *
     * @param string $title Embed title
     * @param string $description Embed description
     * @param array<string, mixed> $context Context for fields
     * @param int $color Embed color
     * @return array<string, mixed>
     */
    private function buildEmbed(string $title, string $description, array $context, int $color): array
    {
        $embed = [
            'title' => $title,
            'color' => $color,
            'timestamp' => date('c'),
            'footer' => [
                'text' => 'Security Shield',
            ],
        ];

        if ($description !== '') {
            $embed['description'] = $description;
        }

        if (!empty($context)) {
            $embed['fields'] = $this->buildFields($context);
        }

        return $embed;
    }

    /**
     * Build embed fields from context
     *
     * @param array<string, mixed> $context
     * @return array<int, array{name: string, value: string, inline: bool}>
     */
    private function buildFields(array $context): array
    {
        $fields = [];

        foreach ($context as $key => $value) {
            $formattedValue = is_array($value)
                ? '```json' . "\n" . json_encode($value, JSON_PRETTY_PRINT) . "\n```"
                : (string) $value;

            $fields[] = [
                'name' => ucfirst(str_replace('_', ' ', $key)),
                'value' => mb_substr($formattedValue, 0, 1024), // Discord limit
                'inline' => strlen($formattedValue) < 50,
            ];
        }

        return $fields;
    }

    /**
     * Make HTTP request to Discord
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

            // Discord returns 204 No Content on success
            return $httpCode === 204 || $httpCode === 200;

        } catch (\Throwable $e) {
            return false;
        }
    }
}
