<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Telegram Notifier.
 *
 * Sends notifications via Telegram Bot API.
 *
 * SETUP:
 * 1. Create a bot with @BotFather on Telegram
 * 2. Get your bot token (e.g., 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ)
 * 3. Get your chat ID:
 *    - Send a message to your bot
 *    - Visit: https://api.telegram.org/bot<TOKEN>/getUpdates
 *    - Find "chat":{"id": YOUR_CHAT_ID}
 *
 * USAGE:
 * ```php
 * $telegram = new TelegramNotifier('BOT_TOKEN', 'CHAT_ID');
 *
 * // Simple message
 * $telegram->send('Server is under attack!');
 *
 * // Alert with details
 * $telegram->alert('🚨 Security Alert', 'IP banned: 1.2.3.4', [
 *     'reason' => 'Honeypot access',
 *     'score' => 100,
 * ]);
 * ```
 */
class TelegramNotifier implements NotifierInterface
{
    private const API_BASE = 'https://api.telegram.org/bot';

    private string $botToken;

    private string $chatId;

    private int $timeout;

    private bool $disableNotification;

    private ?string $parseMode;

    /**
     * @param string $botToken Telegram Bot API token
     * @param string $chatId Chat ID to send messages to
     * @param int $timeout Request timeout in seconds
     * @param bool $disableNotification Send silently
     * @param string|null $parseMode Parse mode (HTML, Markdown, MarkdownV2, null)
     */
    public function __construct(
        string $botToken,
        string $chatId,
        int $timeout = 10,
        bool $disableNotification = false,
        ?string $parseMode = 'HTML',
    ) {
        $this->botToken = $botToken;
        $this->chatId = $chatId;
        $this->timeout = $timeout;
        $this->disableNotification = $disableNotification;
        $this->parseMode = $parseMode;
    }

    public function getName(): string
    {
        return 'telegram';
    }

    public function isConfigured(): bool
    {
        return !empty($this->botToken) && !empty($this->chatId);
    }

    public function send(string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        // Append context if provided
        if (!empty($context)) {
            $message .= "\n\n" . $this->formatContext($context);
        }

        return $this->sendMessage($message);
    }

    public function alert(string $title, string $message, array $context = []): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $fullMessage = "<b>{$this->escapeHtml($title)}</b>\n\n";
        $fullMessage .= $this->escapeHtml($message);

        if (!empty($context)) {
            $fullMessage .= "\n\n" . $this->formatContext($context);
        }

        $fullMessage .= "\n\n<i>" . date('Y-m-d H:i:s T') . '</i>';

        return $this->sendMessage($fullMessage);
    }

    /**
     * Send a message with inline keyboard buttons.
     *
     * @param string $message Message text
     * @param array<int, array<int, array{text: string, url?: string, callback_data?: string}>> $buttons Button rows
     *
     * @return bool
     */
    public function sendWithButtons(string $message, array $buttons): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $keyboard = ['inline_keyboard' => $buttons];

        return $this->sendMessage($message, $keyboard);
    }

    /**
     * Send a document/file.
     *
     * @param string $filePath Path to file or URL
     * @param string|null $caption Optional caption
     *
     * @return bool
     */
    public function sendDocument(string $filePath, ?string $caption = null): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $url = self::API_BASE . $this->botToken . '/sendDocument';

        $data = [
            'chat_id' => $this->chatId,
            'disable_notification' => $this->disableNotification,
        ];

        if ($caption !== null) {
            $data['caption'] = $caption;
        }

        // Check if it's a URL or file path
        if (filter_var($filePath, FILTER_VALIDATE_URL)) {
            $data['document'] = $filePath;

            return $this->request($url, $data);
        }

        // File upload
        if (!file_exists($filePath)) {
            return false;
        }

        $data['document'] = new \CURLFile($filePath);

        return $this->requestMultipart($url, $data);
    }

    /**
     * Send location.
     *
     * @param float $latitude Latitude
     * @param float $longitude Longitude
     *
     * @return bool
     */
    public function sendLocation(float $latitude, float $longitude): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $url = self::API_BASE . $this->botToken . '/sendLocation';

        return $this->request($url, [
            'chat_id' => $this->chatId,
            'latitude' => $latitude,
            'longitude' => $longitude,
            'disable_notification' => $this->disableNotification,
        ]);
    }

    /**
     * Send message via Telegram API.
     *
     * @param string $text Message text
     * @param array<string, mixed>|null $replyMarkup Optional reply markup (keyboard)
     *
     * @return bool
     */
    private function sendMessage(string $text, ?array $replyMarkup = null): bool
    {
        $url = self::API_BASE . $this->botToken . '/sendMessage';

        $data = [
            'chat_id' => $this->chatId,
            'text' => $text,
            'disable_notification' => $this->disableNotification,
        ];

        if ($this->parseMode !== null) {
            $data['parse_mode'] = $this->parseMode;
        }

        if ($replyMarkup !== null) {
            $data['reply_markup'] = json_encode($replyMarkup);
        }

        return $this->request($url, $data);
    }

    /**
     * Make HTTP request to Telegram API.
     *
     * @param string $url API endpoint
     * @param array<string, mixed> $data Request data
     *
     * @return bool
     */
    private function request(string $url, array $data): bool
    {
        try {
            $ch = curl_init();

            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($data),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/x-www-form-urlencoded',
                ],
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if (!is_string($response) || $httpCode !== 200) {
                return false;
            }

            $result = json_decode($response, true);

            return is_array($result) && ($result['ok'] ?? false) === true;

        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Make multipart HTTP request (for file uploads).
     *
     * @param string $url API endpoint
     * @param array<string, mixed> $data Request data
     *
     * @return bool
     */
    private function requestMultipart(string $url, array $data): bool
    {
        try {
            $ch = curl_init();

            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $data,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeout,
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if (!is_string($response) || $httpCode !== 200) {
                return false;
            }

            $result = json_decode($response, true);

            return is_array($result) && ($result['ok'] ?? false) === true;

        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Format context data for display.
     *
     * @param array<string, mixed> $context
     *
     * @return string
     */
    private function formatContext(array $context): string
    {
        $lines = [];

        foreach ($context as $key => $value) {
            $formattedKey = ucfirst(str_replace('_', ' ', $key));
            $formattedValue = is_array($value) ? json_encode($value) : (string) $value;
            $lines[] = "<b>{$this->escapeHtml($formattedKey)}:</b> <code>{$this->escapeHtml($formattedValue)}</code>";
        }

        return implode("\n", $lines);
    }

    /**
     * Escape HTML entities for Telegram HTML parse mode.
     *
     * @param string $text
     *
     * @return string
     */
    private function escapeHtml(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
