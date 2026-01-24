<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Notifications\DiscordNotifier;
use Senza1dio\SecurityShield\Notifications\NotificationManager;
use Senza1dio\SecurityShield\Notifications\SlackNotifier;
use Senza1dio\SecurityShield\Notifications\TelegramNotifier;

/**
 * Integration tests for notification channels.
 *
 * These tests require real credentials to run.
 * Set environment variables before running:
 *
 * TELEGRAM_BOT_TOKEN=your_bot_token
 * TELEGRAM_CHAT_ID=your_chat_id
 * SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
 * DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/XXX/YYY
 *
 * Run with: vendor/bin/phpunit tests/Integration/NotificationsIntegrationTest.php
 *
 * @group integration
 */
class NotificationsIntegrationTest extends TestCase
{
    public function testTelegramNotifier(): void
    {
        $token = getenv('TELEGRAM_BOT_TOKEN');
        $chatId = getenv('TELEGRAM_CHAT_ID');

        if (!$token || !$chatId) {
            $this->markTestSkipped('TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID required');
        }

        $telegram = new TelegramNotifier($token, $chatId);

        $this->assertTrue($telegram->isConfigured());

        // Test simple message
        $result = $telegram->send('🧪 Test message from Security Shield integration test');
        $this->assertTrue($result, 'Failed to send simple message');

        // Test alert
        $result = $telegram->alert('🧪 Test Alert', 'This is a test alert from integration tests', [
            'environment' => 'testing',
            'timestamp' => date('c'),
            'score' => 42,
        ]);
        $this->assertTrue($result, 'Failed to send alert');
    }

    public function testSlackNotifier(): void
    {
        $webhookUrl = getenv('SLACK_WEBHOOK_URL');

        if (!$webhookUrl) {
            $this->markTestSkipped('SLACK_WEBHOOK_URL required');
        }

        $slack = new SlackNotifier($webhookUrl);

        $this->assertTrue($slack->isConfigured());

        // Test simple message
        $result = $slack->send('🧪 Test message from Security Shield integration test');
        $this->assertTrue($result, 'Failed to send simple message');

        // Test alert
        $result = $slack->alert('🧪 Test Alert', 'This is a test alert from integration tests', [
            'environment' => 'testing',
            'timestamp' => date('c'),
            'score' => 42,
        ]);
        $this->assertTrue($result, 'Failed to send alert');
    }

    public function testDiscordNotifier(): void
    {
        $webhookUrl = getenv('DISCORD_WEBHOOK_URL');

        if (!$webhookUrl) {
            $this->markTestSkipped('DISCORD_WEBHOOK_URL required');
        }

        $discord = new DiscordNotifier($webhookUrl);

        $this->assertTrue($discord->isConfigured());

        // Test simple message
        $result = $discord->send('🧪 Test message from Security Shield integration test');
        $this->assertTrue($result, 'Failed to send simple message');

        // Test alert
        $result = $discord->alert('🧪 Test Alert', 'This is a test alert from integration tests', [
            'environment' => 'testing',
            'timestamp' => date('c'),
            'score' => 42,
        ]);
        $this->assertTrue($result, 'Failed to send alert');

        // Test success/warning
        $result = $discord->success('✅ Success', 'Operation completed successfully');
        $this->assertTrue($result, 'Failed to send success');

        $result = $discord->warning('⚠️ Warning', 'Something needs attention');
        $this->assertTrue($result, 'Failed to send warning');
    }

    public function testNotificationManagerBroadcast(): void
    {
        $manager = new NotificationManager();
        $channelsAdded = 0;

        // Add available channels
        $token = getenv('TELEGRAM_BOT_TOKEN');
        $chatId = getenv('TELEGRAM_CHAT_ID');
        if ($token && $chatId) {
            $manager->addChannel(new TelegramNotifier($token, $chatId));
            $channelsAdded++;
        }

        $slackUrl = getenv('SLACK_WEBHOOK_URL');
        if ($slackUrl) {
            $manager->addChannel(new SlackNotifier($slackUrl));
            $channelsAdded++;
        }

        $discordUrl = getenv('DISCORD_WEBHOOK_URL');
        if ($discordUrl) {
            $manager->addChannel(new DiscordNotifier($discordUrl));
            $channelsAdded++;
        }

        if ($channelsAdded === 0) {
            $this->markTestSkipped('No notification channels configured');
        }

        $result = $manager->broadcast(
            '🧪 Broadcast Test',
            'This message was broadcast to all channels',
            [
                'test_id' => uniqid(),
                'channels' => $channelsAdded,
                'timestamp' => date('c'),
            ]
        );

        $this->assertTrue($result->anySuccessful(), 'At least one channel should succeed');
        $this->assertSame($channelsAdded, $result->successCount(), 'All configured channels should succeed');
    }
}
