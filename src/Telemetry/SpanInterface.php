<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * Span Interface
 *
 * Defines the contract for span implementations.
 * Both real Span and NoOpSpan implement this interface.
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
interface SpanInterface
{
    /**
     * Get trace ID
     */
    public function getTraceId(): string;

    /**
     * Get span ID
     */
    public function getSpanId(): string;

    /**
     * Get parent span ID
     */
    public function getParentSpanId(): ?string;

    /**
     * Get span name
     */
    public function getName(): string;

    /**
     * Get span kind
     */
    public function getKind(): SpanKind;

    /**
     * Set a single attribute
     *
     * @param string $key Attribute key
     * @param mixed $value Attribute value
     * @return self
     */
    public function setAttribute(string $key, mixed $value): self;

    /**
     * Set multiple attributes
     *
     * @param array<string, mixed> $attributes
     * @return self
     */
    public function setAttributes(array $attributes): self;

    /**
     * Get all attributes
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array;

    /**
     * Add an event to the span
     *
     * @param string $name Event name
     * @param array<string, mixed> $attributes Event attributes
     * @param float|null $timestamp Event timestamp
     * @return self
     */
    public function addEvent(string $name, array $attributes = [], ?float $timestamp = null): self;

    /**
     * Record an exception as an event
     *
     * @param \Throwable $exception
     * @param array<string, mixed> $attributes
     * @return self
     */
    public function recordException(\Throwable $exception, array $attributes = []): self;

    /**
     * Get all events
     *
     * @return array<int, array{name: string, timestamp: float, attributes: array<string, mixed>}>
     */
    public function getEvents(): array;

    /**
     * Add a link to another span
     *
     * @param string $traceId
     * @param string $spanId
     * @param array<string, mixed> $attributes
     * @return self
     */
    public function addLink(string $traceId, string $spanId, array $attributes = []): self;

    /**
     * Get all links
     *
     * @return array<int, array{context: array<string, string>, attributes: array<string, mixed>}>
     */
    public function getLinks(): array;

    /**
     * Set span status
     *
     * @param SpanStatus $status
     * @param string|null $message
     * @return self
     */
    public function setStatus(SpanStatus $status, ?string $message = null): self;

    /**
     * Get span status
     */
    public function getStatus(): SpanStatus;

    /**
     * Get status message
     */
    public function getStatusMessage(): ?string;

    /**
     * End the span
     *
     * @param float|null $endTime
     * @return self
     */
    public function end(?float $endTime = null): self;

    /**
     * Check if span is still recording
     */
    public function isRecording(): bool;

    /**
     * Get start time
     */
    public function getStartTime(): float;

    /**
     * Get end time
     */
    public function getEndTime(): ?float;

    /**
     * Get duration in seconds
     */
    public function getDuration(): ?float;

    /**
     * Get duration in milliseconds
     */
    public function getDurationMs(): ?float;

    /**
     * Export span to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;
}
