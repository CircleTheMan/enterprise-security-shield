<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * OpenTelemetry-compatible Span
 *
 * Represents a single operation within a trace.
 *
 * USAGE:
 * ```php
 * $span = new Span('operation.name', SpanKind::SERVER);
 * $span->setAttribute('user.id', '12345');
 * $span->addEvent('validation.started');
 *
 * try {
 *     // ... operation
 *     $span->setStatus(SpanStatus::OK);
 * } catch (\Throwable $e) {
 *     $span->recordException($e);
 * } finally {
 *     $span->end();
 * }
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
class Span implements SpanInterface
{
    private string $traceId;
    private string $spanId;
    private ?string $parentSpanId;
    private string $name;
    private SpanKind $kind;
    private SpanStatus $status = SpanStatus::UNSET;
    private ?string $statusMessage = null;

    private float $startTime;
    private ?float $endTime = null;

    /** @var array<string, mixed> */
    private array $attributes = [];

    /** @var array<int, array{name: string, timestamp: float, attributes: array<string, mixed>}> */
    private array $events = [];

    /** @var array<int, array{context: array<string, string>, attributes: array<string, mixed>}> */
    private array $links = [];

    private bool $isRecording = true;

    /**
     * @param string $name Span name
     * @param SpanKind $kind Span kind
     * @param string|null $traceId Trace ID (auto-generated if null)
     * @param string|null $parentSpanId Parent span ID (null for root)
     */
    public function __construct(
        string $name,
        SpanKind $kind = SpanKind::INTERNAL,
        ?string $traceId = null,
        ?string $parentSpanId = null
    ) {
        $this->name = $name;
        $this->kind = $kind;
        $this->traceId = $traceId ?? $this->generateTraceId();
        $this->spanId = $this->generateSpanId();
        $this->parentSpanId = $parentSpanId;
        $this->startTime = microtime(true);
    }

    // ==================== IDENTITY ====================

    /**
     * Get trace ID
     */
    public function getTraceId(): string
    {
        return $this->traceId;
    }

    /**
     * Get span ID
     */
    public function getSpanId(): string
    {
        return $this->spanId;
    }

    /**
     * Get parent span ID
     */
    public function getParentSpanId(): ?string
    {
        return $this->parentSpanId;
    }

    /**
     * Get span name
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get span kind
     */
    public function getKind(): SpanKind
    {
        return $this->kind;
    }

    // ==================== ATTRIBUTES ====================

    /**
     * Set a single attribute
     *
     * @param string $key Attribute key
     * @param mixed $value Attribute value (scalar, array, or null)
     */
    public function setAttribute(string $key, mixed $value): self
    {
        if ($this->isRecording) {
            $this->attributes[$key] = $value;
        }

        return $this;
    }

    /**
     * Set multiple attributes
     *
     * @param array<string, mixed> $attributes
     */
    public function setAttributes(array $attributes): self
    {
        if ($this->isRecording) {
            $this->attributes = array_merge($this->attributes, $attributes);
        }

        return $this;
    }

    /**
     * Get all attributes
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    // ==================== EVENTS ====================

    /**
     * Add an event to the span
     *
     * @param string $name Event name
     * @param array<string, mixed> $attributes Event attributes
     * @param float|null $timestamp Event timestamp (null for now)
     */
    public function addEvent(string $name, array $attributes = [], ?float $timestamp = null): self
    {
        if ($this->isRecording) {
            $this->events[] = [
                'name' => $name,
                'timestamp' => $timestamp ?? microtime(true),
                'attributes' => $attributes,
            ];
        }

        return $this;
    }

    /**
     * Record an exception as an event
     *
     * @param \Throwable $exception The exception to record
     * @param array<string, mixed> $attributes Additional attributes
     */
    public function recordException(\Throwable $exception, array $attributes = []): self
    {
        $exceptionAttributes = array_merge([
            'exception.type' => get_class($exception),
            'exception.message' => $exception->getMessage(),
            'exception.stacktrace' => $exception->getTraceAsString(),
        ], $attributes);

        $this->addEvent('exception', $exceptionAttributes);
        $this->setStatus(SpanStatus::ERROR, $exception->getMessage());

        return $this;
    }

    /**
     * Get all events
     *
     * @return array<int, array{name: string, timestamp: float, attributes: array<string, mixed>}>
     */
    public function getEvents(): array
    {
        return $this->events;
    }

    // ==================== LINKS ====================

    /**
     * Add a link to another span
     *
     * @param string $traceId Linked trace ID
     * @param string $spanId Linked span ID
     * @param array<string, mixed> $attributes Link attributes
     */
    public function addLink(string $traceId, string $spanId, array $attributes = []): self
    {
        if ($this->isRecording) {
            $this->links[] = [
                'context' => [
                    'trace_id' => $traceId,
                    'span_id' => $spanId,
                ],
                'attributes' => $attributes,
            ];
        }

        return $this;
    }

    /**
     * Get all links
     *
     * @return array<int, array{context: array<string, string>, attributes: array<string, mixed>}>
     */
    public function getLinks(): array
    {
        return $this->links;
    }

    // ==================== STATUS ====================

    /**
     * Set span status
     *
     * @param SpanStatus $status Status code
     * @param string|null $message Status message (for ERROR status)
     */
    public function setStatus(SpanStatus $status, ?string $message = null): self
    {
        // Status can only be set if current is UNSET, or upgrading from OK to ERROR
        if ($this->status === SpanStatus::UNSET ||
            ($this->status === SpanStatus::OK && $status === SpanStatus::ERROR)) {
            $this->status = $status;
            $this->statusMessage = $message;
        }

        return $this;
    }

    /**
     * Get span status
     */
    public function getStatus(): SpanStatus
    {
        return $this->status;
    }

    /**
     * Get status message
     */
    public function getStatusMessage(): ?string
    {
        return $this->statusMessage;
    }

    // ==================== LIFECYCLE ====================

    /**
     * End the span
     *
     * @param float|null $endTime End timestamp (null for now)
     */
    public function end(?float $endTime = null): self
    {
        if ($this->isRecording) {
            $this->endTime = $endTime ?? microtime(true);
            $this->isRecording = false;
        }

        return $this;
    }

    /**
     * Check if span is still recording
     */
    public function isRecording(): bool
    {
        return $this->isRecording;
    }

    /**
     * Get start time
     */
    public function getStartTime(): float
    {
        return $this->startTime;
    }

    /**
     * Get end time (null if not ended)
     */
    public function getEndTime(): ?float
    {
        return $this->endTime;
    }

    /**
     * Get duration in seconds (null if not ended)
     */
    public function getDuration(): ?float
    {
        if ($this->endTime === null) {
            return null;
        }

        return $this->endTime - $this->startTime;
    }

    /**
     * Get duration in milliseconds (null if not ended)
     */
    public function getDurationMs(): ?float
    {
        $duration = $this->getDuration();
        return $duration !== null ? $duration * 1000 : null;
    }

    // ==================== EXPORT ====================

    /**
     * Export span to array (OTLP-compatible format)
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'trace_id' => $this->traceId,
            'span_id' => $this->spanId,
            'parent_span_id' => $this->parentSpanId,
            'name' => $this->name,
            'kind' => $this->kind->value,
            'start_time_unix_nano' => (int) ($this->startTime * 1_000_000_000),
            'end_time_unix_nano' => $this->endTime !== null
                ? (int) ($this->endTime * 1_000_000_000)
                : null,
            'attributes' => $this->formatAttributes($this->attributes),
            'events' => array_map(fn($event) => [
                'name' => $event['name'],
                'time_unix_nano' => (int) ($event['timestamp'] * 1_000_000_000),
                'attributes' => $this->formatAttributes($event['attributes']),
            ], $this->events),
            'links' => $this->links,
            'status' => [
                'code' => $this->status->value,
                'message' => $this->statusMessage,
            ],
        ];
    }

    // ==================== PRIVATE METHODS ====================

    /**
     * Generate a 32-character trace ID
     */
    private function generateTraceId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Generate a 16-character span ID
     */
    private function generateSpanId(): string
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * Format attributes for OTLP export
     *
     * @param array<string, mixed> $attributes
     * @return array<int, array{key: string, value: array<string, mixed>}>
     */
    private function formatAttributes(array $attributes): array
    {
        $formatted = [];

        foreach ($attributes as $key => $value) {
            $formatted[] = [
                'key' => $key,
                'value' => $this->formatAttributeValue($value),
            ];
        }

        return $formatted;
    }

    /**
     * Format a single attribute value for OTLP
     *
     * @param mixed $value
     * @return array<string, mixed>
     */
    private function formatAttributeValue(mixed $value): array
    {
        if (is_string($value)) {
            return ['string_value' => $value];
        }

        if (is_int($value)) {
            return ['int_value' => $value];
        }

        if (is_float($value)) {
            return ['double_value' => $value];
        }

        if (is_bool($value)) {
            return ['bool_value' => $value];
        }

        if (is_array($value)) {
            return ['array_value' => ['values' => array_map(
                fn($v) => $this->formatAttributeValue($v),
                $value
            )]];
        }

        return ['string_value' => (string) $value];
    }
}
