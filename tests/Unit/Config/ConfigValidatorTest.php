<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Config;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Config\ConfigValidator;

class ConfigValidatorTest extends TestCase
{
    public function testRequiredPasses(): void
    {
        $validator = ConfigValidator::create()->required();

        $result = $validator->validate('value');

        $this->assertTrue($result->valid);
    }

    public function testRequiredFails(): void
    {
        $validator = ConfigValidator::create()->required();

        $result = $validator->validate(null);

        $this->assertFalse($result->valid);
        $this->assertSame('Value is required', $result->error);
    }

    public function testOptionalAllowsNull(): void
    {
        $validator = ConfigValidator::create()->type('string');

        $result = $validator->validate(null);

        $this->assertTrue($result->valid);
    }

    public function testTypeString(): void
    {
        $validator = ConfigValidator::create()->type('string');

        $this->assertTrue($validator->validate('hello')->valid);
        $this->assertFalse($validator->validate(123)->valid);
    }

    public function testTypeInteger(): void
    {
        $validator = ConfigValidator::create()->type('integer');

        $this->assertTrue($validator->validate(42)->valid);
        $this->assertTrue($validator->validate('123')->valid); // Numeric string OK
        $this->assertFalse($validator->validate('hello')->valid);
    }

    public function testTypeFloat(): void
    {
        $validator = ConfigValidator::create()->type('float');

        $this->assertTrue($validator->validate(3.14)->valid);
        $this->assertTrue($validator->validate(42)->valid); // Int is also float
        $this->assertTrue($validator->validate('3.14')->valid); // Numeric string OK
    }

    public function testTypeBoolean(): void
    {
        $validator = ConfigValidator::create()->type('boolean');

        $this->assertTrue($validator->validate(true)->valid);
        $this->assertTrue($validator->validate(false)->valid);
        $this->assertTrue($validator->validate('true')->valid);
        $this->assertTrue($validator->validate('1')->valid);
        $this->assertTrue($validator->validate(0)->valid);
    }

    public function testTypeArray(): void
    {
        $validator = ConfigValidator::create()->type('array');

        $this->assertTrue($validator->validate([1, 2, 3])->valid);
        $this->assertTrue($validator->validate(['key' => 'value'])->valid);
        $this->assertFalse($validator->validate('not array')->valid);
    }

    public function testMinNumber(): void
    {
        $validator = ConfigValidator::create()->type('integer')->min(10);

        $this->assertTrue($validator->validate(10)->valid);
        $this->assertTrue($validator->validate(100)->valid);
        $this->assertFalse($validator->validate(5)->valid);
    }

    public function testMaxNumber(): void
    {
        $validator = ConfigValidator::create()->type('integer')->max(100);

        $this->assertTrue($validator->validate(100)->valid);
        $this->assertTrue($validator->validate(50)->valid);
        $this->assertFalse($validator->validate(150)->valid);
    }

    public function testMinMaxRange(): void
    {
        $validator = ConfigValidator::create()->type('integer')->min(1)->max(100);

        $this->assertTrue($validator->validate(50)->valid);
        $this->assertFalse($validator->validate(0)->valid);
        $this->assertFalse($validator->validate(101)->valid);
    }

    public function testMinStringLength(): void
    {
        $validator = ConfigValidator::create()->type('string')->min(5);

        $this->assertTrue($validator->validate('hello')->valid);
        $this->assertTrue($validator->validate('hello world')->valid);
        $this->assertFalse($validator->validate('hi')->valid);
    }

    public function testMaxStringLength(): void
    {
        $validator = ConfigValidator::create()->type('string')->max(10);

        $this->assertTrue($validator->validate('hello')->valid);
        $this->assertFalse($validator->validate('hello world!')->valid);
    }

    public function testMinMaxArraySize(): void
    {
        $validator = ConfigValidator::create()->type('array')->min(2)->max(5);

        $this->assertTrue($validator->validate([1, 2, 3])->valid);
        $this->assertFalse($validator->validate([1])->valid);
        $this->assertFalse($validator->validate([1, 2, 3, 4, 5, 6])->valid);
    }

    public function testOneOf(): void
    {
        $validator = ConfigValidator::create()->oneOf(['debug', 'info', 'warning', 'error']);

        $this->assertTrue($validator->validate('info')->valid);
        $this->assertTrue($validator->validate('error')->valid);
        $this->assertFalse($validator->validate('trace')->valid);
    }

    public function testPattern(): void
    {
        $validator = ConfigValidator::create()->type('string')->pattern('/^[a-z_]+$/');

        $this->assertTrue($validator->validate('hello_world')->valid);
        $this->assertFalse($validator->validate('Hello World')->valid);
        $this->assertFalse($validator->validate('123')->valid);
    }

    public function testCustomValidator(): void
    {
        $validator = ConfigValidator::create()->custom(function ($value) {
            if ($value % 2 !== 0) {
                return 'Value must be even';
            }
            return true;
        });

        $this->assertTrue($validator->validate(4)->valid);
        $this->assertFalse($validator->validate(5)->valid);
        $this->assertSame('Value must be even', $validator->validate(5)->error);
    }

    public function testChainedValidation(): void
    {
        $validator = ConfigValidator::create()
            ->required()
            ->type('integer')
            ->min(1)
            ->max(1000);

        $this->assertTrue($validator->validate(500)->valid);
        $this->assertFalse($validator->validate(null)->valid);
        $this->assertFalse($validator->validate('hello')->valid);
        $this->assertFalse($validator->validate(0)->valid);
        $this->assertFalse($validator->validate(1001)->valid);
    }

    public function testValidationResultOrThrow(): void
    {
        $validator = ConfigValidator::create()->required();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Value is required');

        $validator->validate(null)->orThrow();
    }

    public function testValidationResultIfValid(): void
    {
        $validator = ConfigValidator::create()->required();
        $called = false;

        $validator->validate('value')->ifValid(function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function testValidationResultIfInvalid(): void
    {
        $validator = ConfigValidator::create()->required();
        $errorMessage = null;

        $validator->validate(null)->ifInvalid(function (string $error) use (&$errorMessage) {
            $errorMessage = $error;
        });

        $this->assertSame('Value is required', $errorMessage);
    }
}
