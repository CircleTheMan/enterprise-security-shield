<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Notifications;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Notifications\TelegramNotifier;

class TelegramNotifierTest extends TestCase
{
    public function testGetName(): void
    {
        $notifier = new TelegramNotifier('token', 'chatid');

        $this->assertSame('telegram', $notifier->getName());
    }

    public function testIsConfiguredWithValidConfig(): void
    {
        $notifier = new TelegramNotifier('123456789:ABCdef', '123456789');

        $this->assertTrue($notifier->isConfigured());
    }

    public function testIsConfiguredWithEmptyToken(): void
    {
        $notifier = new TelegramNotifier('', '123456789');

        $this->assertFalse($notifier->isConfigured());
    }

    public function testIsConfiguredWithEmptyChatId(): void
    {
        $notifier = new TelegramNotifier('123456789:ABCdef', '');

        $this->assertFalse($notifier->isConfigured());
    }

    public function testSendReturnsFalseWhenNotConfigured(): void
    {
        $notifier = new TelegramNotifier('', '');

        $result = $notifier->send('Test message');

        $this->assertFalse($result);
    }

    public function testAlertReturnsFalseWhenNotConfigured(): void
    {
        $notifier = new TelegramNotifier('', '');

        $result = $notifier->alert('Title', 'Message');

        $this->assertFalse($result);
    }
}
