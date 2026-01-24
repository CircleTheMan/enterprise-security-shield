<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Exporters;

use Senza1dio\SecurityShield\Telemetry\SpanExporterInterface;

/**
 * File Exporter.
 *
 * Exports spans to a file in JSONL (JSON Lines) format.
 * Supports log rotation.
 *
 * USAGE:
 * ```php
 * $exporter = new FileExporter('/var/log/traces.jsonl');
 * $exporter->setMaxFileSize(10 * 1024 * 1024); // 10MB rotation
 *
 * $tracer = new Tracer('my-service');
 * $tracer->addExporter($exporter);
 * ```
 */
class FileExporter implements SpanExporterInterface
{
    private string $filePath;

    private ?int $maxFileSize;

    private int $maxRotations;

    /** @var resource|null */
    private $handle = null;

    /**
     * @param string $filePath Path to trace file
     * @param int|null $maxFileSize Max file size before rotation (null for no rotation)
     * @param int $maxRotations Number of rotated files to keep
     */
    public function __construct(
        string $filePath,
        ?int $maxFileSize = null,
        int $maxRotations = 5,
    ) {
        $this->filePath = $filePath;
        $this->maxFileSize = $maxFileSize;
        $this->maxRotations = $maxRotations;

        $this->ensureDirectory();
    }

    /**
     * Set maximum file size before rotation.
     */
    public function setMaxFileSize(int $bytes): self
    {
        $this->maxFileSize = $bytes;

        return $this;
    }

    /**
     * Set number of rotations to keep.
     */
    public function setMaxRotations(int $count): self
    {
        $this->maxRotations = $count;

        return $this;
    }

    public function export(array $exportData): bool
    {
        // Check for rotation
        if ($this->maxFileSize !== null && $this->shouldRotate()) {
            $this->rotate();
        }

        $handle = $this->getHandle();

        if ($handle === null) {
            return false;
        }

        // Write each span as a separate JSON line
        foreach ($exportData['scope_spans'] ?? [] as $scopeSpan) {
            foreach ($scopeSpan['spans'] ?? [] as $span) {
                $line = json_encode([
                    'timestamp' => date('c'),
                    'resource' => $exportData['resource'] ?? [],
                    'scope' => $scopeSpan['scope'] ?? [],
                    'span' => $span,
                ], JSON_UNESCAPED_SLASHES);

                if ($line !== false) {
                    fwrite($handle, $line . "\n");
                }
            }
        }

        fflush($handle);

        return true;
    }

    public function shutdown(): void
    {
        if ($this->handle !== null) {
            fclose($this->handle);
            $this->handle = null;
        }
    }

    /**
     * Get file handle.
     *
     * @return resource|null
     */
    private function getHandle()
    {
        if ($this->handle === null) {
            $opened = fopen($this->filePath, 'a');
            $this->handle = $opened !== false ? $opened : null;
        }

        return $this->handle;
    }

    /**
     * Check if file should be rotated.
     */
    private function shouldRotate(): bool
    {
        if (!file_exists($this->filePath)) {
            return false;
        }

        $size = filesize($this->filePath);

        return $size !== false && $size >= $this->maxFileSize;
    }

    /**
     * Rotate log files.
     */
    private function rotate(): void
    {
        // Close current handle
        if ($this->handle !== null) {
            fclose($this->handle);
            $this->handle = null;
        }

        // Remove oldest rotation
        $oldestFile = "{$this->filePath}.{$this->maxRotations}";
        if (file_exists($oldestFile)) {
            unlink($oldestFile);
        }

        // Shift existing rotations
        for ($i = $this->maxRotations - 1; $i >= 1; $i--) {
            $oldFile = "{$this->filePath}.{$i}";
            $newFile = "{$this->filePath}." . ($i + 1);

            if (file_exists($oldFile)) {
                rename($oldFile, $newFile);
            }
        }

        // Rotate current file
        if (file_exists($this->filePath)) {
            rename($this->filePath, "{$this->filePath}.1");
        }
    }

    /**
     * Ensure directory exists.
     */
    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);

        if (!is_dir($dir)) {
            mkdir($dir, 0o755, true);
        }
    }
}
