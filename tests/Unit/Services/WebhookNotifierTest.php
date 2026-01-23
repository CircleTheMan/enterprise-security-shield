<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Services;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Services\WebhookNotifier;

/**
 * Webhook Notifier Test Suite
 *
 * @covers \Senza1dio\SecurityShield\Services\WebhookNotifier
 */
class WebhookNotifierTest extends TestCase
{
    private WebhookNotifier $notifier;

    protected function setUp(): void
    {
        $this->notifier = new WebhookNotifier();
    }

    public function testAddWebhookValid(): void
    {
        $this->notifier->addWebhook('slack', 'https://hooks.slack.com/services/T00/B00/XXX');

        $this->expectNotToPerformAssertions();
    }

    public function testAddWebhookInvalidThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid webhook URL');

        $this->notifier->addWebhook('invalid', 'not-a-url');
    }

    public function testAddWebhookLocalhostBlocked(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Webhook URL cannot be localhost');

        $this->notifier->addWebhook('local', 'http://localhost/webhook');
    }

    public function testAddWebhookPrivateIPBlocked(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Webhook URL cannot be private IP');

        $this->notifier->addWebhook('private', 'http://192.168.1.1/webhook');
    }

    public function testSetTimeoutValid(): void
    {
        $this->notifier->setTimeout(5);

        $this->expectNotToPerformAssertions();
    }

    public function testSetAsyncEnablesAsync(): void
    {
        $this->notifier->setAsync(true);

        $this->expectNotToPerformAssertions();
    }

    public function testSetAsyncDisablesAsync(): void
    {
        $this->notifier->setAsync(false);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Integration test - requires network
     * @group integration
     */
    public function testNotifyRealWebhook(): void
    {
        // Use a webhook testing service like webhook.site
        // This test is skipped by default - run with --group integration
        $this->markTestSkipped('Requires real webhook endpoint for testing');

        $this->notifier->addWebhook('test', 'https://webhook.site/unique-id');
        $this->notifier->notify('test_event', [
            'ip' => '192.168.1.1',
            'reason' => 'Test notification',
        ]);

        // No assertion - check webhook.site for received data
        $this->expectNotToPerformAssertions();
    }
}
