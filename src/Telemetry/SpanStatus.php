<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * OpenTelemetry Span Status
 *
 * Status of a span indicating success or error.
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
enum SpanStatus: string
{
    /**
     * Unset - default status
     */
    case UNSET = 'unset';

    /**
     * OK - operation completed successfully
     */
    case OK = 'ok';

    /**
     * Error - operation failed
     */
    case ERROR = 'error';
}
