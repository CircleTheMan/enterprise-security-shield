<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry\Exporters;

use Senza1dio\SecurityShield\Telemetry\SpanExporterInterface;

/**
 * Console Exporter
 *
 * Exports spans to STDOUT for debugging and development.
 *
 * USAGE:
 * ```php
 * $exporter = new ConsoleExporter(pretty: true);
 * $tracer = new Tracer('my-service');
 * $tracer->addExporter($exporter);
 * ```
 *
 * @package Senza1dio\SecurityShield\Telemetry\Exporters
 */
class ConsoleExporter implements SpanExporterInterface
{
    private bool $pretty;
    private bool $colors;

    /** @var resource|null */
    private $stream;

    /**
     * @param bool $pretty Pretty-print JSON
     * @param bool $colors Enable ANSI colors
     * @param resource|null $stream Output stream (null for STDOUT)
     */
    public function __construct(
        bool $pretty = true,
        bool $colors = true,
        $stream = null
    ) {
        $this->pretty = $pretty;
        $this->colors = $colors && $this->supportsColors();
        $this->stream = $stream;
    }

    public function export(array $exportData): bool
    {
        $output = $this->stream ?? STDOUT;

        if ($this->pretty) {
            $this->exportPretty($exportData, $output);
        } else {
            $json = json_encode($exportData, JSON_UNESCAPED_SLASHES);
            fwrite($output, $json . "\n");
        }

        return true;
    }

    public function shutdown(): void
    {
        // Nothing to do
    }

    /**
     * Export with pretty formatting
     *
     * @param array<string, mixed> $exportData
     * @param resource $output
     */
    private function exportPretty(array $exportData, $output): void
    {
        $serviceName = $exportData['resource']['attributes'][0]['value']['string_value'] ?? 'unknown';

        fwrite($output, $this->color("\n═══════════════════════════════════════════════════════════════\n", 'cyan'));
        fwrite($output, $this->color(" TRACE EXPORT ", 'white', 'blue') . " ");
        fwrite($output, $this->color("Service: {$serviceName}", 'yellow') . "\n");
        fwrite($output, $this->color("═══════════════════════════════════════════════════════════════\n", 'cyan'));

        foreach ($exportData['scope_spans'] ?? [] as $scopeSpan) {
            foreach ($scopeSpan['spans'] ?? [] as $span) {
                $this->printSpan($span, $output);
            }
        }

        fwrite($output, "\n");
    }

    /**
     * Print a single span
     *
     * @param array<string, mixed> $span
     * @param resource $output
     */
    private function printSpan(array $span, $output): void
    {
        $name = $span['name'] ?? 'unknown';
        $kind = $span['kind'] ?? 'internal';
        $status = $span['status']['code'] ?? 'unset';
        $traceId = substr($span['trace_id'] ?? '', 0, 8) . '...';
        $spanId = $span['span_id'] ?? '';
        $parentId = $span['parent_span_id'] ?? null;

        $startNano = $span['start_time_unix_nano'] ?? 0;
        $endNano = $span['end_time_unix_nano'] ?? $startNano;
        $durationMs = ($endNano - $startNano) / 1_000_000;

        // Status color
        $statusColor = match ($status) {
            'ok' => 'green',
            'error' => 'red',
            default => 'white',
        };

        // Print span header
        fwrite($output, "\n");
        fwrite($output, $this->color("┌─ ", 'gray'));
        fwrite($output, $this->color($name, 'white'));
        fwrite($output, $this->color(" [{$kind}]", 'gray'));
        fwrite($output, "\n");

        // Print span details
        fwrite($output, $this->color("│  ", 'gray'));
        fwrite($output, $this->color("Trace: ", 'gray') . $this->color($traceId, 'cyan'));
        fwrite($output, $this->color("  Span: ", 'gray') . $this->color($spanId, 'cyan'));

        if ($parentId) {
            fwrite($output, $this->color("  Parent: ", 'gray') . $this->color($parentId, 'cyan'));
        }

        fwrite($output, "\n");

        fwrite($output, $this->color("│  ", 'gray'));
        fwrite($output, $this->color("Duration: ", 'gray') . $this->color(sprintf('%.2fms', $durationMs), 'yellow'));
        fwrite($output, $this->color("  Status: ", 'gray') . $this->color($status, $statusColor));
        fwrite($output, "\n");

        // Print attributes
        if (!empty($span['attributes'])) {
            fwrite($output, $this->color("│  ", 'gray'));
            fwrite($output, $this->color("Attributes:", 'gray') . "\n");

            foreach ($span['attributes'] as $attr) {
                $key = $attr['key'] ?? '';
                $value = $this->formatAttributeValue($attr['value'] ?? []);
                fwrite($output, $this->color("│    ", 'gray'));
                fwrite($output, $this->color($key, 'magenta') . ": " . $this->color($value, 'white') . "\n");
            }
        }

        // Print events
        if (!empty($span['events'])) {
            fwrite($output, $this->color("│  ", 'gray'));
            fwrite($output, $this->color("Events:", 'gray') . "\n");

            foreach ($span['events'] as $event) {
                $eventName = $event['name'] ?? '';
                $isException = $eventName === 'exception';
                $eventColor = $isException ? 'red' : 'cyan';

                fwrite($output, $this->color("│    ", 'gray'));
                fwrite($output, $this->color("• ", $eventColor) . $this->color($eventName, $eventColor) . "\n");

                if ($isException && !empty($event['attributes'])) {
                    foreach ($event['attributes'] as $attr) {
                        $key = $attr['key'] ?? '';
                        if (str_starts_with($key, 'exception.')) {
                            $value = $this->formatAttributeValue($attr['value'] ?? []);
                            $shortValue = strlen($value) > 60 ? substr($value, 0, 57) . '...' : $value;
                            fwrite($output, $this->color("│      ", 'gray'));
                            fwrite($output, $this->color($key, 'red') . ": " . $shortValue . "\n");
                        }
                    }
                }
            }
        }

        fwrite($output, $this->color("└─────", 'gray') . "\n");
    }

    /**
     * Format attribute value for display
     *
     * @param array<string, mixed> $value
     */
    private function formatAttributeValue(array $value): string
    {
        if (isset($value['string_value'])) {
            return '"' . $value['string_value'] . '"';
        }

        if (isset($value['int_value'])) {
            return (string) $value['int_value'];
        }

        if (isset($value['double_value'])) {
            return (string) $value['double_value'];
        }

        if (isset($value['bool_value'])) {
            return $value['bool_value'] ? 'true' : 'false';
        }

        if (isset($value['array_value'])) {
            return '[array]';
        }

        return json_encode($value) ?: 'unknown';
    }

    /**
     * Apply ANSI color to text
     */
    private function color(string $text, string $color, ?string $background = null): string
    {
        if (!$this->colors) {
            return $text;
        }

        $colors = [
            'black' => '30',
            'red' => '31',
            'green' => '32',
            'yellow' => '33',
            'blue' => '34',
            'magenta' => '35',
            'cyan' => '36',
            'white' => '37',
            'gray' => '90',
        ];

        $backgrounds = [
            'black' => '40',
            'red' => '41',
            'green' => '42',
            'yellow' => '43',
            'blue' => '44',
            'magenta' => '45',
            'cyan' => '46',
            'white' => '47',
        ];

        $codes = [];

        if (isset($colors[$color])) {
            $codes[] = $colors[$color];
        }

        if ($background !== null && isset($backgrounds[$background])) {
            $codes[] = $backgrounds[$background];
        }

        if (empty($codes)) {
            return $text;
        }

        return "\033[" . implode(';', $codes) . "m{$text}\033[0m";
    }

    /**
     * Check if terminal supports colors
     */
    private function supportsColors(): bool
    {
        if (PHP_SAPI !== 'cli') {
            return false;
        }

        if (DIRECTORY_SEPARATOR === '\\') {
            return getenv('ANSICON') !== false ||
                   getenv('ConEmuANSI') === 'ON' ||
                   getenv('TERM') === 'xterm';
        }

        return posix_isatty(STDOUT);
    }
}
