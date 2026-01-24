<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Detected Anomaly
 *
 * Represents a single detected anomaly with all relevant context.
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
class Anomaly
{
    private string $id;
    private AnomalyType $type;
    private AnomalySeverity $severity;
    private float $score;
    private string $description;
    private float $timestamp;

    /** @var array<string, mixed> */
    private array $context;

    /** @var array<string, mixed> */
    private array $metadata;

    /**
     * @param AnomalyType $type Anomaly type
     * @param float $score Anomaly score (0.0 - 1.0)
     * @param string $description Human-readable description
     * @param array<string, mixed> $context Contextual data
     * @param array<string, mixed> $metadata Additional metadata
     */
    public function __construct(
        AnomalyType $type,
        float $score,
        string $description,
        array $context = [],
        array $metadata = []
    ) {
        $this->id = bin2hex(random_bytes(16));
        $this->type = $type;
        $this->score = max(0.0, min(1.0, $score));
        $this->severity = AnomalySeverity::fromScore($this->score);
        $this->description = $description;
        $this->context = $context;
        $this->metadata = $metadata;
        $this->timestamp = microtime(true);
    }

    /**
     * Get unique anomaly ID
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Get anomaly type
     */
    public function getType(): AnomalyType
    {
        return $this->type;
    }

    /**
     * Get severity level
     */
    public function getSeverity(): AnomalySeverity
    {
        return $this->severity;
    }

    /**
     * Get anomaly score (0.0 - 1.0)
     */
    public function getScore(): float
    {
        return $this->score;
    }

    /**
     * Get human-readable description
     */
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * Get timestamp
     */
    public function getTimestamp(): float
    {
        return $this->timestamp;
    }

    /**
     * Get context data
     *
     * @return array<string, mixed>
     */
    public function getContext(): array
    {
        return $this->context;
    }

    /**
     * Get specific context value
     */
    public function getContextValue(string $key, mixed $default = null): mixed
    {
        return $this->context[$key] ?? $default;
    }

    /**
     * Get metadata
     *
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    /**
     * Set a metadata value
     *
     * @param string $key Metadata key
     * @param mixed $value Metadata value
     * @return self
     */
    public function setMetadata(string $key, mixed $value): self
    {
        $this->metadata[$key] = $value;
        return $this;
    }

    /**
     * Merge metadata values
     *
     * @param array<string, mixed> $metadata Metadata to merge
     * @return self
     */
    public function mergeMetadata(array $metadata): self
    {
        $this->metadata = array_merge($this->metadata, $metadata);
        return $this;
    }

    /**
     * Check if severity is at least the given level
     */
    public function isSeverityAtLeast(AnomalySeverity $minSeverity): bool
    {
        return $this->severity->score() >= $minSeverity->score();
    }

    /**
     * Export to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type->value,
            'severity' => $this->severity->value,
            'score' => $this->score,
            'description' => $this->description,
            'timestamp' => $this->timestamp,
            'timestamp_iso' => date('c', (int) $this->timestamp),
            'context' => $this->context,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Export to JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR);
    }
}
