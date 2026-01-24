<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Notifications;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Notifications\NotificationManager;
use Senza1dio\SecurityShield\Notifications\NotifierInterface;

class NotificationManagerTest extends TestCase
{
    public function testAddChannel(): void
    {
        $manager = new NotificationManager();
        $notifier = $this->createMockNotifier('test');

        $manager->addChannel($notifier);

        $this->assertSame($notifier, $manager->getChannel('test'));
    }

    public function testRemoveChannel(): void
    {
        $manager = new NotificationManager();
        $notifier = $this->createMockNotifier('test');

        $manager->addChannel($notifier);
        $manager->removeChannel('test');

        $this->assertNull($manager->getChannel('test'));
    }

    public function testEnableDisableChannel(): void
    {
        $manager = new NotificationManager();
        $notifier = $this->createMockNotifier('test');

        $manager->addChannel($notifier, true);
        $this->assertTrue($manager->isEnabled('test'));

        $manager->disable('test');
        $this->assertFalse($manager->isEnabled('test'));

        $manager->enable('test');
        $this->assertTrue($manager->isEnabled('test'));
    }

    public function testGetEnabledChannels(): void
    {
        $manager = new NotificationManager();
        $notifier1 = $this->createMockNotifier('enabled');
        $notifier2 = $this->createMockNotifier('disabled');

        $manager->addChannel($notifier1, true);
        $manager->addChannel($notifier2, false);

        $enabled = $manager->getEnabledChannels();

        $this->assertCount(1, $enabled);
        $this->assertArrayHasKey('enabled', $enabled);
        $this->assertArrayNotHasKey('disabled', $enabled);
    }

    public function testBroadcast(): void
    {
        $manager = new NotificationManager();

        $notifier1 = $this->createMockNotifier('channel1', true, true);
        $notifier2 = $this->createMockNotifier('channel2', true, true);

        $notifier1->expects($this->once())->method('alert');
        $notifier2->expects($this->once())->method('alert');

        $manager->addChannel($notifier1);
        $manager->addChannel($notifier2);

        $result = $manager->broadcast('Title', 'Message', ['key' => 'value']);

        $this->assertTrue($result->allSuccessful());
    }

    public function testNotifySpecificChannels(): void
    {
        $manager = new NotificationManager();

        $notifier1 = $this->createMockNotifier('channel1', true, true);
        $notifier2 = $this->createMockNotifier('channel2', true, true);

        $notifier1->expects($this->once())->method('alert');
        $notifier2->expects($this->never())->method('alert');

        $manager->addChannel($notifier1);
        $manager->addChannel($notifier2);

        $result = $manager->notify(['channel1'], 'Title', 'Message');

        $this->assertTrue($result->allSuccessful());
    }

    public function testNotifyNonExistentChannel(): void
    {
        $manager = new NotificationManager();

        $result = $manager->notify(['nonexistent'], 'Title', 'Message');

        $this->assertTrue($result->allFailed());
        $this->assertNotNull($result->getError('nonexistent'));
    }

    public function testNotifyUnconfiguredChannel(): void
    {
        $manager = new NotificationManager();

        $notifier = $this->createMockNotifier('unconfigured', false);
        $manager->addChannel($notifier);

        $result = $manager->notify(['unconfigured'], 'Title', 'Message');

        $this->assertTrue($result->allFailed());
        $this->assertSame('Channel not configured', $result->getError('unconfigured'));
    }

    public function testGetStatus(): void
    {
        $manager = new NotificationManager();

        $notifier1 = $this->createMockNotifier('configured', true);
        $notifier2 = $this->createMockNotifier('unconfigured', false);

        $manager->addChannel($notifier1, true);
        $manager->addChannel($notifier2, false);

        $status = $manager->getStatus();

        $this->assertSame(['enabled' => true, 'configured' => true], $status['configured']);
        $this->assertSame(['enabled' => false, 'configured' => false], $status['unconfigured']);
    }

    public function testNotificationResult(): void
    {
        $manager = new NotificationManager();

        $success = $this->createMockNotifier('success', true, true);
        $failure = $this->createMockNotifier('failure', true, false);

        $manager->addChannel($success);
        $manager->addChannel($failure);

        $result = $manager->broadcast('Title', 'Message');

        $this->assertFalse($result->allSuccessful());
        $this->assertTrue($result->anySuccessful());
        $this->assertSame(1, $result->successCount());
        $this->assertSame(1, $result->failureCount());
        $this->assertContains('success', $result->getSuccessful());
        $this->assertContains('failure', $result->getFailed());
    }

    /**
     * Create mock notifier
     *
     * @param string $name
     * @param bool $configured
     * @param bool $sendSuccess
     * @return NotifierInterface&\PHPUnit\Framework\MockObject\MockObject
     */
    private function createMockNotifier(
        string $name,
        bool $configured = true,
        bool $sendSuccess = true
    ): NotifierInterface {
        $mock = $this->createMock(NotifierInterface::class);

        $mock->method('getName')->willReturn($name);
        $mock->method('isConfigured')->willReturn($configured);
        $mock->method('send')->willReturn($sendSuccess);
        $mock->method('alert')->willReturn($sendSuccess);

        return $mock;
    }
}
