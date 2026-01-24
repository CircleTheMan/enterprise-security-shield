<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Exporters;

use Senza1dio\SecurityShield\Telemetry\SpanExporterInterface;

/**
 * OTLP HTTP Exporter.
 *
 * Exports spans to an OpenTelemetry collector via OTLP/HTTP.
 *
 * USAGE:
 * ```php
 * $exporter = new OtlpHttpExporter('http://collector:4318/v1/traces');
 * $exporter->setHeaders(['Authorization' => 'Bearer token']);
 *
 * $tracer = new Tracer('my-service');
 * $tracer->addExporter($exporter);
 * ```
 */
class OtlpHttpExporter implements SpanExporterInterface
{
    private string $endpoint;

    /** @var array<string, string> */
    private array $headers = [];

    private int $timeoutMs;

    private bool $compression;

    /**
     * @param string $endpoint OTLP collector endpoint
     * @param int $timeoutMs Request timeout in milliseconds
     * @param bool $compression Enable gzip compression
     */
    public function __construct(
        string $endpoint,
        int $timeoutMs = 10000,
        bool $compression = true,
    ) {
        $this->endpoint = rtrim($endpoint, '/');
        $this->timeoutMs = $timeoutMs;
        $this->compression = $compression;

        $this->headers = [
            'Content-Type' => 'application/json',
        ];
    }

    /**
     * Set custom headers.
     *
     * @param array<string, string> $headers
     */
    public function setHeaders(array $headers): self
    {
        $this->headers = array_merge($this->headers, $headers);

        return $this;
    }

    /**
     * Set authorization token.
     */
    public function setAuthToken(string $token): self
    {
        $this->headers['Authorization'] = "Bearer {$token}";

        return $this;
    }

    public function export(array $exportData): bool
    {
        $json = json_encode($exportData, JSON_THROW_ON_ERROR);

        // Compress if enabled
        $body = $json;
        $headers = $this->headers;

        if ($this->compression && extension_loaded('zlib')) {
            $compressed = gzencode($json);
            if ($compressed !== false) {
                $body = $compressed;
                $headers['Content-Encoding'] = 'gzip';
            }
        }

        // Send request
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => $this->formatHeaders($headers),
                'content' => $body,
                'timeout' => $this->timeoutMs / 1000,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($this->endpoint, false, $context);

        if ($response === false) {
            return false;
        }

        // Check response status
        /** @var array<int, string> $responseHeaders */
        $responseHeaders = $http_response_header;
        $statusCode = $this->getResponseStatusCode($responseHeaders);

        return $statusCode >= 200 && $statusCode < 300;
    }

    public function shutdown(): void
    {
        // Nothing to flush - we export synchronously
    }

    /**
     * Format headers for HTTP context.
     *
     * @param array<string, string> $headers
     *
     * @return string
     */
    private function formatHeaders(array $headers): string
    {
        $lines = [];

        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }

        return implode("\r\n", $lines);
    }

    /**
     * Extract status code from response headers.
     *
     * @param array<int, string> $headers
     */
    private function getResponseStatusCode(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\d\.\d\s+(\d{3})/', $header, $matches)) {
                return (int) $matches[1];
            }
        }

        return 0;
    }
}
