<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit\Telemetry;

use PHPUnit\Framework\TestCase;
use Senza1dio\SecurityShield\Telemetry\Span;
use Senza1dio\SecurityShield\Telemetry\SpanKind;
use Senza1dio\SecurityShield\Telemetry\SpanStatus;

class SpanTest extends TestCase
{
    public function testCreatesWithDefaultValues(): void
    {
        $span = new Span('test.operation');

        $this->assertSame('test.operation', $span->getName());
        $this->assertSame(SpanKind::INTERNAL, $span->getKind());
        $this->assertSame(SpanStatus::UNSET, $span->getStatus());
        $this->assertTrue($span->isRecording());
        $this->assertNull($span->getParentSpanId());
    }

    public function testCreatesWithCustomKind(): void
    {
        $span = new Span('http.request', SpanKind::SERVER);

        $this->assertSame(SpanKind::SERVER, $span->getKind());
    }

    public function testGeneratesUniqueIds(): void
    {
        $span1 = new Span('test');
        $span2 = new Span('test');

        $this->assertNotSame($span1->getTraceId(), $span2->getTraceId());
        $this->assertNotSame($span1->getSpanId(), $span2->getSpanId());
    }

    public function testTraceIdFormat(): void
    {
        $span = new Span('test');

        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $span->getTraceId());
    }

    public function testSpanIdFormat(): void
    {
        $span = new Span('test');

        $this->assertMatchesRegularExpression('/^[a-f0-9]{16}$/', $span->getSpanId());
    }

    public function testInheritsTraceId(): void
    {
        $parentTraceId = str_repeat('a', 32);
        $parentSpanId = str_repeat('b', 16);

        $span = new Span('child', SpanKind::INTERNAL, $parentTraceId, $parentSpanId);

        $this->assertSame($parentTraceId, $span->getTraceId());
        $this->assertSame($parentSpanId, $span->getParentSpanId());
        $this->assertNotSame($parentSpanId, $span->getSpanId());
    }

    public function testSetAttribute(): void
    {
        $span = new Span('test');

        $span->setAttribute('user.id', '12345');
        $span->setAttribute('http.status', 200);

        $attrs = $span->getAttributes();

        $this->assertSame('12345', $attrs['user.id']);
        $this->assertSame(200, $attrs['http.status']);
    }

    public function testSetAttributes(): void
    {
        $span = new Span('test');

        $span->setAttributes([
            'key1' => 'value1',
            'key2' => 'value2',
        ]);

        $attrs = $span->getAttributes();

        $this->assertSame('value1', $attrs['key1']);
        $this->assertSame('value2', $attrs['key2']);
    }

    public function testAddEvent(): void
    {
        $span = new Span('test');

        $span->addEvent('validation.started');
        $span->addEvent('validation.completed', ['valid' => true]);

        $events = $span->getEvents();

        $this->assertCount(2, $events);
        $this->assertSame('validation.started', $events[0]['name']);
        $this->assertSame('validation.completed', $events[1]['name']);
        $this->assertSame(true, $events[1]['attributes']['valid']);
    }

    public function testRecordException(): void
    {
        $span = new Span('test');
        $exception = new \RuntimeException('Something went wrong');

        $span->recordException($exception);

        $events = $span->getEvents();
        $this->assertCount(1, $events);
        $this->assertSame('exception', $events[0]['name']);
        $this->assertSame('RuntimeException', $events[0]['attributes']['exception.type']);
        $this->assertSame('Something went wrong', $events[0]['attributes']['exception.message']);

        $this->assertSame(SpanStatus::ERROR, $span->getStatus());
    }

    public function testAddLink(): void
    {
        $span = new Span('test');

        $span->addLink('trace123', 'span456', ['reason' => 'continuation']);

        $links = $span->getLinks();

        $this->assertCount(1, $links);
        $this->assertSame('trace123', $links[0]['context']['trace_id']);
        $this->assertSame('span456', $links[0]['context']['span_id']);
        $this->assertSame('continuation', $links[0]['attributes']['reason']);
    }

    public function testSetStatus(): void
    {
        $span = new Span('test');

        $span->setStatus(SpanStatus::OK);
        $this->assertSame(SpanStatus::OK, $span->getStatus());

        // Can upgrade from OK to ERROR
        $span->setStatus(SpanStatus::ERROR, 'Failed');
        $this->assertSame(SpanStatus::ERROR, $span->getStatus());
        $this->assertSame('Failed', $span->getStatusMessage());

        // Cannot downgrade from ERROR to OK
        $span->setStatus(SpanStatus::OK);
        $this->assertSame(SpanStatus::ERROR, $span->getStatus());
    }

    public function testEnd(): void
    {
        $span = new Span('test');

        $this->assertNull($span->getEndTime());
        $this->assertTrue($span->isRecording());

        $span->end();

        $this->assertNotNull($span->getEndTime());
        $this->assertFalse($span->isRecording());
    }

    public function testDuration(): void
    {
        $span = new Span('test');

        usleep(10000); // 10ms

        $span->end();

        $duration = $span->getDuration();
        $durationMs = $span->getDurationMs();

        $this->assertNotNull($duration);
        $this->assertNotNull($durationMs);
        $this->assertGreaterThan(0, $duration);
        $this->assertGreaterThan(0, $durationMs);
    }

    public function testAttributesNotRecordedAfterEnd(): void
    {
        $span = new Span('test');
        $span->setAttribute('before', 'yes');
        $span->end();
        $span->setAttribute('after', 'no');

        $attrs = $span->getAttributes();

        $this->assertArrayHasKey('before', $attrs);
        $this->assertArrayNotHasKey('after', $attrs);
    }

    public function testToArray(): void
    {
        $span = new Span('test.operation', SpanKind::SERVER);
        $span->setAttribute('http.method', 'GET');
        $span->addEvent('started');
        $span->setStatus(SpanStatus::OK);
        $span->end();

        $array = $span->toArray();

        $this->assertSame($span->getTraceId(), $array['trace_id']);
        $this->assertSame($span->getSpanId(), $array['span_id']);
        $this->assertSame('test.operation', $array['name']);
        $this->assertSame('server', $array['kind']);
        $this->assertSame('ok', $array['status']['code']);
        $this->assertNotNull($array['start_time_unix_nano']);
        $this->assertNotNull($array['end_time_unix_nano']);
    }
}
