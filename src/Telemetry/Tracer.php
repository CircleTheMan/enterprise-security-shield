<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * OpenTelemetry-compatible Tracer
 *
 * Creates and manages spans for distributed tracing.
 *
 * FEATURES:
 * - Automatic parent-child span relationships
 * - Context propagation
 * - Multiple exporters support
 * - Sampling strategies
 *
 * USAGE:
 * ```php
 * $tracer = new Tracer('security-shield');
 * $tracer->addExporter(new OtlpExporter('http://collector:4318'));
 *
 * $span = $tracer->startSpan('request.process', SpanKind::SERVER);
 * $span->setAttribute('http.method', 'POST');
 *
 * $childSpan = $tracer->startSpan('honeypot.check');
 * // ... do work
 * $childSpan->end();
 *
 * $span->end();
 * $tracer->flush();
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
class Tracer
{
    private string $serviceName;
    private string $serviceVersion;

    /** @var array<string, mixed> */
    private array $resourceAttributes = [];

    /** @var array<int, SpanExporterInterface> */
    private array $exporters = [];

    /** @var array<int, SpanInterface> */
    private array $activeSpans = [];

    /** @var array<int, Span> */
    private array $finishedSpans = [];

    /** @var array<int, SpanInterface> */
    private array $activeSpansAll = [];

    private ?SamplerInterface $sampler = null;
    private int $maxQueueSize = 2048;
    private int $batchSize = 512;

    /**
     * @param string $serviceName Service name for traces
     * @param string $serviceVersion Service version
     * @param array<string, mixed> $resourceAttributes Additional resource attributes
     */
    public function __construct(
        string $serviceName,
        string $serviceVersion = '1.0.0',
        array $resourceAttributes = []
    ) {
        $this->serviceName = $serviceName;
        $this->serviceVersion = $serviceVersion;
        $this->resourceAttributes = array_merge([
            'service.name' => $serviceName,
            'service.version' => $serviceVersion,
            'telemetry.sdk.name' => 'security-shield',
            'telemetry.sdk.language' => 'php',
            'telemetry.sdk.version' => '1.0.0',
        ], $resourceAttributes);
    }

    // ==================== CONFIGURATION ====================

    /**
     * Add a span exporter
     */
    public function addExporter(SpanExporterInterface $exporter): self
    {
        $this->exporters[] = $exporter;
        return $this;
    }

    /**
     * Set sampler for trace sampling
     */
    public function setSampler(SamplerInterface $sampler): self
    {
        $this->sampler = $sampler;
        return $this;
    }

    /**
     * Set maximum queue size before forced flush
     */
    public function setMaxQueueSize(int $size): self
    {
        $this->maxQueueSize = $size;
        return $this;
    }

    /**
     * Set batch size for exports
     */
    public function setBatchSize(int $size): self
    {
        $this->batchSize = $size;
        return $this;
    }

    /**
     * Get resource attributes
     *
     * @return array<string, mixed>
     */
    public function getResourceAttributes(): array
    {
        return $this->resourceAttributes;
    }

    // ==================== SPAN MANAGEMENT ====================

    /**
     * Start a new span
     *
     * @param string $name Span name
     * @param SpanKind $kind Span kind
     * @param array<string, mixed> $attributes Initial attributes
     * @param SpanInterface|null $parent Parent span (null for auto-detect or root)
     */
    public function startSpan(
        string $name,
        SpanKind $kind = SpanKind::INTERNAL,
        array $attributes = [],
        ?SpanInterface $parent = null
    ): SpanInterface {
        // Determine parent
        $parentSpan = $parent ?? $this->getCurrentSpan();
        $traceId = $parentSpan?->getTraceId();
        $parentSpanId = $parentSpan?->getSpanId();

        // Check sampling (only for root spans)
        if ($traceId === null && $this->sampler !== null) {
            if (!$this->sampler->shouldSample($name, $kind, $attributes)) {
                // Return a no-op span that doesn't record
                $noOp = new NoOpSpan($name);
                $this->activeSpansAll[] = $noOp;
                return $noOp;
            }
        }

        $span = new Span($name, $kind, $traceId, $parentSpanId);
        $span->setAttributes($attributes);

        $this->activeSpans[] = $span;
        $this->activeSpansAll[] = $span;

        return $span;
    }

    /**
     * Get current active span
     */
    public function getCurrentSpan(): ?SpanInterface
    {
        $count = count($this->activeSpansAll);
        return $count > 0 ? $this->activeSpansAll[$count - 1] : null;
    }

    /**
     * End a span and queue for export
     */
    public function endSpan(SpanInterface $span): void
    {
        $span->end();

        // Remove from all active spans tracking
        $this->activeSpansAll = array_values(array_filter(
            $this->activeSpansAll,
            fn($s) => $s->getSpanId() !== $span->getSpanId()
        ));

        // Skip NoOpSpan - don't add to export queue
        if ($span instanceof NoOpSpan) {
            return;
        }

        // Remove from active spans (real spans only)
        $this->activeSpans = array_values(array_filter(
            $this->activeSpans,
            fn($s) => $s->getSpanId() !== $span->getSpanId()
        ));

        // Add to finished spans queue (only real Span instances)
        if ($span instanceof Span) {
            $this->finishedSpans[] = $span;
        }

        // Auto-flush if queue is full
        if (count($this->finishedSpans) >= $this->maxQueueSize) {
            $this->flush();
        }
    }

    /**
     * Execute a callable within a span
     *
     * @template T
     * @param string $name Span name
     * @param callable(): T $operation Operation to execute
     * @param SpanKind $kind Span kind
     * @param array<string, mixed> $attributes Initial attributes
     * @return T Operation result
     */
    public function trace(
        string $name,
        callable $operation,
        SpanKind $kind = SpanKind::INTERNAL,
        array $attributes = []
    ): mixed {
        $span = $this->startSpan($name, $kind, $attributes);

        try {
            $result = $operation();
            $span->setStatus(SpanStatus::OK);
            return $result;
        } catch (\Throwable $e) {
            $span->recordException($e);
            throw $e;
        } finally {
            $this->endSpan($span);
        }
    }

    // ==================== CONTEXT PROPAGATION ====================

    /**
     * Extract trace context from headers (W3C Trace Context format)
     *
     * @param array<string, string|array<string>> $headers Request headers
     * @return array{trace_id: string|null, span_id: string|null, trace_flags: int}
     */
    public function extractContext(array $headers): array
    {
        $traceParent = $this->getHeader($headers, 'traceparent');

        if ($traceParent === null) {
            return ['trace_id' => null, 'span_id' => null, 'trace_flags' => 0];
        }

        // Parse: version-trace_id-parent_id-trace_flags
        // Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
        $parts = explode('-', $traceParent);

        if (count($parts) !== 4 || $parts[0] !== '00') {
            return ['trace_id' => null, 'span_id' => null, 'trace_flags' => 0];
        }

        return [
            'trace_id' => $parts[1],
            'span_id' => $parts[2],
            'trace_flags' => (int) hexdec($parts[3]),
        ];
    }

    /**
     * Inject trace context into headers (W3C Trace Context format)
     *
     * @param SpanInterface $span Span to inject context from
     * @return array<string, string> Headers to add to outgoing request
     */
    public function injectContext(SpanInterface $span): array
    {
        return [
            'traceparent' => sprintf(
                '00-%s-%s-01',
                $span->getTraceId(),
                $span->getSpanId()
            ),
            'tracestate' => '',
        ];
    }

    /**
     * Start a span with extracted context
     *
     * @param string $name Span name
     * @param array<string, string|array<string>> $headers Request headers
     * @param SpanKind $kind Span kind
     * @param array<string, mixed> $attributes Initial attributes
     */
    public function startSpanFromContext(
        string $name,
        array $headers,
        SpanKind $kind = SpanKind::SERVER,
        array $attributes = []
    ): Span {
        $context = $this->extractContext($headers);

        $span = new Span(
            $name,
            $kind,
            $context['trace_id'],
            $context['span_id']
        );

        $span->setAttributes($attributes);
        $this->activeSpans[] = $span;

        return $span;
    }

    // ==================== EXPORT ====================

    /**
     * Flush finished spans to exporters
     *
     * @return int Number of spans flushed (even if no exporters configured)
     */
    public function flush(): int
    {
        if (empty($this->finishedSpans)) {
            return 0;
        }

        $spans = $this->finishedSpans;
        $this->finishedSpans = [];

        // If no exporters, still report the count of flushed spans
        if (empty($this->exporters)) {
            return count($spans);
        }

        // Export in batches
        $batches = array_chunk($spans, $this->batchSize);
        $exported = 0;

        foreach ($batches as $batch) {
            $exportData = [
                'resource' => [
                    'attributes' => $this->formatResourceAttributes(),
                ],
                'scope_spans' => [
                    [
                        'scope' => [
                            'name' => $this->serviceName,
                            'version' => $this->serviceVersion,
                        ],
                        'spans' => array_map(fn($s) => $s->toArray(), $batch),
                    ],
                ],
            ];

            foreach ($this->exporters as $exporter) {
                try {
                    $exporter->export($exportData);
                } catch (\Throwable $e) {
                    // Log but don't fail - telemetry should not break the app
                    error_log("Telemetry export failed: " . $e->getMessage());
                }
            }

            $exported += count($batch);
        }

        return $exported;
    }

    /**
     * Shutdown tracer and flush remaining spans
     */
    public function shutdown(): void
    {
        // End any remaining active spans
        foreach ($this->activeSpans as $span) {
            $span->end();
            $this->finishedSpans[] = $span;
        }

        $this->activeSpans = [];
        $this->activeSpansAll = [];
        $this->flush();

        // Shutdown exporters
        foreach ($this->exporters as $exporter) {
            try {
                $exporter->shutdown();
            } catch (\Throwable $e) {
                error_log("Exporter shutdown failed: " . $e->getMessage());
            }
        }
    }

    /**
     * Get number of pending spans
     */
    public function getPendingSpanCount(): int
    {
        return count($this->finishedSpans);
    }

    /**
     * Get number of active spans
     */
    public function getActiveSpanCount(): int
    {
        return count($this->activeSpans);
    }

    // ==================== PRIVATE METHODS ====================

    /**
     * Get header value (case-insensitive)
     *
     * @param array<string, string|array<string>> $headers
     * @param string $name Header name
     */
    private function getHeader(array $headers, string $name): ?string
    {
        $lowerName = strtolower($name);

        foreach ($headers as $key => $value) {
            if (strtolower($key) === $lowerName) {
                return is_array($value) ? ($value[0] ?? null) : $value;
            }
        }

        return null;
    }

    /**
     * Format resource attributes for export
     *
     * @return array<int, array{key: string, value: array<string, mixed>}>
     */
    private function formatResourceAttributes(): array
    {
        $formatted = [];

        foreach ($this->resourceAttributes as $key => $value) {
            $formatted[] = [
                'key' => $key,
                'value' => $this->formatAttributeValue($value),
            ];
        }

        return $formatted;
    }

    /**
     * Format a single attribute value
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

        return ['string_value' => (string) $value];
    }
}
