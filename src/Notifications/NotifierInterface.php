<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Notifications;

/**
 * Notifier Interface
 *
 * Contract for notification channels (Telegram, Slack, Discord, etc.)
 *
 * @package Senza1dio\SecurityShield\Notifications
 */
interface NotifierInterface
{
    /**
     * Send a notification
     *
     * @param string $message Message to send
     * @param array<string, mixed> $context Additional context data
     * @return bool True if sent successfully
     */
    public function send(string $message, array $context = []): bool;

    /**
     * Send an alert (high priority notification)
     *
     * @param string $title Alert title
     * @param string $message Alert message
     * @param array<string, mixed> $context Additional context data
     * @return bool True if sent successfully
     */
    public function alert(string $title, string $message, array $context = []): bool;

    /**
     * Get notifier name
     */
    public function getName(): string;

    /**
     * Check if notifier is properly configured
     */
    public function isConfigured(): bool;
}
