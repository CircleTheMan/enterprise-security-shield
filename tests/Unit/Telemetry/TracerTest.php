<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Telemetry;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Telemetry\NoOpSpan;
use Senza1dio\SecurityShield\Telemetry\Samplers\AlwaysOffSampler;
use Senza1dio\SecurityShield\Telemetry\Samplers\AlwaysOnSampler;
use Senza1dio\SecurityShield\Telemetry\Samplers\RatioBasedSampler;
use Senza1dio\SecurityShield\Telemetry\SpanKind;
use Senza1dio\SecurityShield\Telemetry\SpanStatus;
use Senza1dio\SecurityShield\Telemetry\Tracer;

class TracerTest extends TestCase
{
    public function testCreatesWithServiceInfo(): void
    {
        $tracer = new Tracer('my-service', '1.0.0');

        $attrs = $tracer->getResourceAttributes();

        $this->assertSame('my-service', $attrs['service.name']);
        $this->assertSame('1.0.0', $attrs['service.version']);
    }

    public function testStartSpan(): void
    {
        $tracer = new Tracer('test');

        $span = $tracer->startSpan('operation.name', SpanKind::SERVER);

        $this->assertSame('operation.name', $span->getName());
        $this->assertSame(SpanKind::SERVER, $span->getKind());
        $this->assertTrue($span->isRecording());
    }

    public function testStartSpanWithAttributes(): void
    {
        $tracer = new Tracer('test');

        $span = $tracer->startSpan('operation', SpanKind::INTERNAL, [
            'user.id' => '123',
            'request.id' => 'abc',
        ]);

        $attrs = $span->getAttributes();

        $this->assertSame('123', $attrs['user.id']);
        $this->assertSame('abc', $attrs['request.id']);
    }

    public function testChildSpanInheritsTraceId(): void
    {
        $tracer = new Tracer('test');

        $parent = $tracer->startSpan('parent');
        $child = $tracer->startSpan('child');

        $this->assertSame($parent->getTraceId(), $child->getTraceId());
        $this->assertSame($parent->getSpanId(), $child->getParentSpanId());
    }

    public function testGetCurrentSpan(): void
    {
        $tracer = new Tracer('test');

        $this->assertNull($tracer->getCurrentSpan());

        $span = $tracer->startSpan('test');

        $this->assertSame($span, $tracer->getCurrentSpan());
    }

    public function testEndSpanRemovesFromStack(): void
    {
        $tracer = new Tracer('test');

        $span = $tracer->startSpan('test');
        $this->assertSame($span, $tracer->getCurrentSpan());

        $tracer->endSpan($span);
        $this->assertNull($tracer->getCurrentSpan());
    }

    public function testTrace(): void
    {
        $tracer = new Tracer('test');

        $result = $tracer->trace('operation', function () {
            return 'success';
        });

        $this->assertSame('success', $result);
    }

    public function testTraceRecordsException(): void
    {
        $tracer = new Tracer('test');

        $this->expectException(\RuntimeException::class);

        try {
            $tracer->trace('failing', function () {
                throw new \RuntimeException('oops');
            });
        } finally {
            // Span should have been ended
            $this->assertNull($tracer->getCurrentSpan());
        }
    }

    public function testExtractContext(): void
    {
        $tracer = new Tracer('test');

        $headers = [
            'traceparent' => '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
        ];

        $context = $tracer->extractContext($headers);

        $this->assertSame('0af7651916cd43dd8448eb211c80319c', $context['trace_id']);
        $this->assertSame('b7ad6b7169203331', $context['span_id']);
        $this->assertSame(1, $context['trace_flags']);
    }

    public function testExtractContextInvalidFormat(): void
    {
        $tracer = new Tracer('test');

        $context = $tracer->extractContext(['traceparent' => 'invalid']);

        $this->assertNull($context['trace_id']);
        $this->assertNull($context['span_id']);
    }

    public function testInjectContext(): void
    {
        $tracer = new Tracer('test');
        $span = $tracer->startSpan('test');

        $headers = $tracer->injectContext($span);

        $this->assertArrayHasKey('traceparent', $headers);
        $this->assertStringStartsWith('00-', $headers['traceparent']);
        $this->assertStringContainsString($span->getTraceId(), $headers['traceparent']);
        $this->assertStringContainsString($span->getSpanId(), $headers['traceparent']);
    }

    public function testStartSpanFromContext(): void
    {
        $tracer = new Tracer('test');

        $headers = [
            'traceparent' => '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
        ];

        $span = $tracer->startSpanFromContext('incoming', $headers, SpanKind::SERVER);

        $this->assertSame('0af7651916cd43dd8448eb211c80319c', $span->getTraceId());
        $this->assertSame('b7ad6b7169203331', $span->getParentSpanId());
    }

    public function testAlwaysOnSampler(): void
    {
        $tracer = new Tracer('test');
        $tracer->setSampler(new AlwaysOnSampler());

        $span = $tracer->startSpan('test');

        $this->assertTrue($span->isRecording());
        $this->assertNotInstanceOf(NoOpSpan::class, $span);
    }

    public function testAlwaysOffSampler(): void
    {
        $tracer = new Tracer('test');
        $tracer->setSampler(new AlwaysOffSampler());

        $span = $tracer->startSpan('test');

        $this->assertInstanceOf(NoOpSpan::class, $span);
        $this->assertFalse($span->isRecording());
    }

    public function testRatioBasedSampler(): void
    {
        $tracer = new Tracer('test');
        $tracer->setSampler(new RatioBasedSampler(0.0));

        $span = $tracer->startSpan('test');

        $this->assertInstanceOf(NoOpSpan::class, $span);

        // With 100% ratio
        $tracer->setSampler(new RatioBasedSampler(1.0));
        $span = $tracer->startSpan('test');

        $this->assertNotInstanceOf(NoOpSpan::class, $span);
    }

    public function testFlush(): void
    {
        $tracer = new Tracer('test');

        $span1 = $tracer->startSpan('span1');
        $tracer->endSpan($span1);

        $span2 = $tracer->startSpan('span2');
        $tracer->endSpan($span2);

        $this->assertSame(2, $tracer->getPendingSpanCount());

        $exported = $tracer->flush();

        $this->assertSame(2, $exported);
        $this->assertSame(0, $tracer->getPendingSpanCount());
    }

    public function testShutdown(): void
    {
        $tracer = new Tracer('test');

        // Start some spans without ending
        $tracer->startSpan('active1');
        $tracer->startSpan('active2');

        $this->assertSame(2, $tracer->getActiveSpanCount());

        $tracer->shutdown();

        $this->assertSame(0, $tracer->getActiveSpanCount());
        $this->assertSame(0, $tracer->getPendingSpanCount());
    }
}
