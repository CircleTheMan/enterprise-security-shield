<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Anomaly;

/**
 * Anomaly Types
 *
 * Classification of detected anomalies.
 *
 * @package Senza1dio\SecurityShield\Anomaly
 */
enum AnomalyType: string
{
    /**
     * Unusual request rate (spike or drop)
     */
    case RATE_ANOMALY = 'rate_anomaly';

    /**
     * Request from unusual geographic location
     */
    case GEO_ANOMALY = 'geo_anomaly';

    /**
     * Request at unusual time (off-hours)
     */
    case TIME_ANOMALY = 'time_anomaly';

    /**
     * Unusual user agent pattern
     */
    case USER_AGENT_ANOMALY = 'user_agent_anomaly';

    /**
     * Unusual request pattern (endpoints, methods)
     */
    case PATTERN_ANOMALY = 'pattern_anomaly';

    /**
     * Unusual session behavior
     */
    case SESSION_ANOMALY = 'session_anomaly';

    /**
     * Statistical outlier in metrics
     */
    case STATISTICAL_ANOMALY = 'statistical_anomaly';

    /**
     * Behavioral deviation from baseline
     */
    case BEHAVIORAL_ANOMALY = 'behavioral_anomaly';
}
