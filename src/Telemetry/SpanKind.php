<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Telemetry;

/**
 * OpenTelemetry Span Kind
 *
 * Defines the relationship between spans for distributed tracing.
 *
 * @package Senza1dio\SecurityShield\Telemetry
 */
enum SpanKind: string
{
    /**
     * Internal span (default)
     * An internal operation within an application.
     */
    case INTERNAL = 'internal';

    /**
     * Server span
     * A span handling an inbound request.
     */
    case SERVER = 'server';

    /**
     * Client span
     * A span making an outbound request.
     */
    case CLIENT = 'client';

    /**
     * Producer span
     * A span initiating an async request.
     */
    case PRODUCER = 'producer';

    /**
     * Consumer span
     * A span processing an async request.
     */
    case CONSUMER = 'consumer';
}
