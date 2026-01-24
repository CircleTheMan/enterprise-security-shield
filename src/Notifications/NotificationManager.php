<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Notification Manager
 *
 * Manages multiple notification channels and dispatches alerts.
 *
 * USAGE:
 * ```php
 * $manager = new NotificationManager();
 *
 * // Add channels
 * $manager->addChannel(new TelegramNotifier('BOT_TOKEN', 'CHAT_ID'));
 * $manager->addChannel(new SlackNotifier('WEBHOOK_URL'));
 * $manager->addChannel(new DiscordNotifier('WEBHOOK_URL'));
 * $manager->addChannel(new EmailNotifier(['security@example.com'], 'from@example.com'));
 *
 * // Send to all channels
 * $manager->broadcast('🚨 Security Alert', 'IP banned: 1.2.3.4', [
 *     'reason' => 'Honeypot access',
 * ]);
 *
 * // Send to specific channels
 * $manager->notify(['telegram', 'slack'], 'Alert', 'Message', $context);
 * ```
 *
 * @package Senza1dio\SecurityShield\Notifications
 */
class NotificationManager
{
    /** @var array<string, NotifierInterface> */
    private array $channels = [];

    /** @var array<string, bool> */
    private array $enabledChannels = [];

    private bool $failSilently = true;

    /**
     * Add notification channel
     *
     * @param NotifierInterface $notifier Notifier instance
     * @param bool $enabled Enable channel by default
     * @return self
     */
    public function addChannel(NotifierInterface $notifier, bool $enabled = true): self
    {
        $name = $notifier->getName();
        $this->channels[$name] = $notifier;
        $this->enabledChannels[$name] = $enabled;

        return $this;
    }

    /**
     * Remove notification channel
     *
     * @param string $name Channel name
     * @return self
     */
    public function removeChannel(string $name): self
    {
        unset($this->channels[$name]);
        unset($this->enabledChannels[$name]);

        return $this;
    }

    /**
     * Enable a channel
     *
     * @param string $name Channel name
     * @return self
     */
    public function enable(string $name): self
    {
        if (isset($this->channels[$name])) {
            $this->enabledChannels[$name] = true;
        }

        return $this;
    }

    /**
     * Disable a channel
     *
     * @param string $name Channel name
     * @return self
     */
    public function disable(string $name): self
    {
        if (isset($this->channels[$name])) {
            $this->enabledChannels[$name] = false;
        }

        return $this;
    }

    /**
     * Set whether to fail silently on errors
     *
     * @param bool $failSilently
     * @return self
     */
    public function setFailSilently(bool $failSilently): self
    {
        $this->failSilently = $failSilently;

        return $this;
    }

    /**
     * Broadcast alert to all enabled channels
     *
     * @param string $title Alert title
     * @param string $message Alert message
     * @param array<string, mixed> $context Additional context
     * @return NotificationResult
     */
    public function broadcast(string $title, string $message, array $context = []): NotificationResult
    {
        return $this->notify(array_keys($this->getEnabledChannels()), $title, $message, $context);
    }

    /**
     * Send to specific channels
     *
     * @param array<string> $channelNames Channel names to notify
     * @param string $title Alert title
     * @param string $message Alert message
     * @param array<string, mixed> $context Additional context
     * @return NotificationResult
     */
    public function notify(array $channelNames, string $title, string $message, array $context = []): NotificationResult
    {
        $results = [];
        $errors = [];

        foreach ($channelNames as $name) {
            if (!isset($this->channels[$name])) {
                $errors[$name] = 'Channel not found';
                continue;
            }

            $channel = $this->channels[$name];

            if (!$channel->isConfigured()) {
                $errors[$name] = 'Channel not configured';
                continue;
            }

            try {
                $success = $channel->alert($title, $message, $context);
                $results[$name] = $success;

                if (!$success) {
                    $errors[$name] = 'Send failed';
                }
            } catch (\Throwable $e) {
                $results[$name] = false;
                $errors[$name] = $e->getMessage();

                if (!$this->failSilently) {
                    throw $e;
                }
            }
        }

        return new NotificationResult($results, $errors);
    }

    /**
     * Send simple message to specific channels
     *
     * @param array<string> $channelNames Channel names
     * @param string $message Message
     * @param array<string, mixed> $context Additional context
     * @return NotificationResult
     */
    public function send(array $channelNames, string $message, array $context = []): NotificationResult
    {
        $results = [];
        $errors = [];

        foreach ($channelNames as $name) {
            if (!isset($this->channels[$name])) {
                $errors[$name] = 'Channel not found';
                continue;
            }

            $channel = $this->channels[$name];

            if (!$channel->isConfigured()) {
                $errors[$name] = 'Channel not configured';
                continue;
            }

            try {
                $success = $channel->send($message, $context);
                $results[$name] = $success;

                if (!$success) {
                    $errors[$name] = 'Send failed';
                }
            } catch (\Throwable $e) {
                $results[$name] = false;
                $errors[$name] = $e->getMessage();

                if (!$this->failSilently) {
                    throw $e;
                }
            }
        }

        return new NotificationResult($results, $errors);
    }

    /**
     * Get a specific channel
     *
     * @param string $name Channel name
     * @return NotifierInterface|null
     */
    public function getChannel(string $name): ?NotifierInterface
    {
        return $this->channels[$name] ?? null;
    }

    /**
     * Get all channels
     *
     * @return array<string, NotifierInterface>
     */
    public function getChannels(): array
    {
        return $this->channels;
    }

    /**
     * Get enabled channels
     *
     * @return array<string, NotifierInterface>
     */
    public function getEnabledChannels(): array
    {
        return array_filter(
            $this->channels,
            fn($name) => $this->enabledChannels[$name] ?? false,
            ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * Check if channel exists and is enabled
     *
     * @param string $name Channel name
     * @return bool
     */
    public function isEnabled(string $name): bool
    {
        return isset($this->channels[$name]) && ($this->enabledChannels[$name] ?? false);
    }

    /**
     * Get channel status
     *
     * @return array<string, array{enabled: bool, configured: bool}>
     */
    public function getStatus(): array
    {
        $status = [];

        foreach ($this->channels as $name => $channel) {
            $status[$name] = [
                'enabled' => $this->enabledChannels[$name] ?? false,
                'configured' => $channel->isConfigured(),
            ];
        }

        return $status;
    }
}
