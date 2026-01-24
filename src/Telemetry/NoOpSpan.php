<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * No-Operation Span.
 *
 * A span that doesn't record anything, used when sampling decides not to trace.
 * Implements SpanInterface for transparent use without inheriting Span.
 */
class NoOpSpan implements SpanInterface
{
    private string $spanId;

    private string $traceId;

    public function __construct()
    {
        $this->spanId = str_repeat('0', 16);
        $this->traceId = str_repeat('0', 32);
    }

    public function getTraceId(): string
    {
        return $this->traceId;
    }

    public function getSpanId(): string
    {
        return $this->spanId;
    }

    public function getParentSpanId(): ?string
    {
        return null;
    }

    public function getName(): string
    {
        return '';
    }

    public function getKind(): SpanKind
    {
        return SpanKind::INTERNAL;
    }

    public function setAttribute(string $key, mixed $value): SpanInterface
    {
        return $this;
    }

    public function setAttributes(array $attributes): SpanInterface
    {
        return $this;
    }

    public function getAttributes(): array
    {
        return [];
    }

    public function addEvent(string $name, array $attributes = [], ?float $timestamp = null): SpanInterface
    {
        return $this;
    }

    public function recordException(\Throwable $exception, array $attributes = []): SpanInterface
    {
        return $this;
    }

    public function getEvents(): array
    {
        return [];
    }

    public function addLink(string $traceId, string $spanId, array $attributes = []): SpanInterface
    {
        return $this;
    }

    public function getLinks(): array
    {
        return [];
    }

    public function setStatus(SpanStatus $status, ?string $message = null): SpanInterface
    {
        return $this;
    }

    public function getStatus(): SpanStatus
    {
        return SpanStatus::UNSET;
    }

    public function getStatusMessage(): ?string
    {
        return null;
    }

    public function end(?float $endTime = null): SpanInterface
    {
        return $this;
    }

    public function isRecording(): bool
    {
        return false;
    }

    public function getStartTime(): float
    {
        return 0.0;
    }

    public function getEndTime(): ?float
    {
        return null;
    }

    public function getDuration(): ?float
    {
        return null;
    }

    public function getDurationMs(): ?float
    {
        return null;
    }

    public function toArray(): array
    {
        return [];
    }
}
