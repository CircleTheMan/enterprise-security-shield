-- ============================================================================
-- ENTERPRISE SECURITY SHIELD - Database Schema (PostgreSQL 17)
-- ============================================================================
--
-- PURPOSE: Persistent storage for security events, bans, and threat scores
--
-- DUAL-WRITE ARCHITECTURE:
-- - Redis: L1 cache (sub-millisecond reads, volatile)
-- - PostgreSQL: Persistent storage (survives restarts, auditing, compliance)
--
-- PERFORMANCE OPTIMIZATIONS:
-- - Composite indexes for common queries
-- - JSONB for flexible event data
-- - Automatic cleanup via retention policies
-- - Hot path queries use Redis (ban checks, rate limits)
-- - Cold path queries use DB (reporting, analytics, compliance)
--
-- COMPATIBILITY: PostgreSQL 9.5+ (JSONB support required)
-- ============================================================================

-- ============================================================================
-- TABLE: ip_bans
-- PURPOSE: Persistent storage of banned IPs for compliance and analytics
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_bans (
    ip VARCHAR(45) NOT NULL,                          -- IPv4 (15 chars) or IPv6 (45 chars)
    reason VARCHAR(255) NOT NULL,                     -- Ban reason (vulnerability scanning, GeoIP, etc.)
    banned_at TIMESTAMP NOT NULL DEFAULT NOW(),       -- When ban was issued
    expires_at TIMESTAMP NOT NULL,                    -- When ban expires (for auto-cleanup)
    ban_count INTEGER NOT NULL DEFAULT 1,             -- Number of times IP has been banned (repeat offender tracking)
    metadata JSONB DEFAULT '{}'::JSONB,              -- Additional data (user_agent, path, threat score, etc.)

    PRIMARY KEY (ip, banned_at),                      -- Allow multiple ban records per IP (history)

    -- Performance indexes
    INDEX idx_ip_bans_expires (expires_at),          -- Cleanup expired bans
    INDEX idx_ip_bans_ip_active (ip, expires_at),    -- Active ban check per IP
    INDEX idx_ip_bans_reason (reason)                 -- Analytics by ban reason
);

-- ============================================================================
-- TABLE: threat_scores
-- PURPOSE: Persistent threat scores for long-term tracking and pattern analysis
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_scores (
    ip VARCHAR(45) NOT NULL PRIMARY KEY,              -- Client IP
    score INTEGER NOT NULL DEFAULT 0,                 -- Current threat score (0-1000)
    last_updated TIMESTAMP NOT NULL DEFAULT NOW(),    -- Last score modification
    expires_at TIMESTAMP NOT NULL,                    -- Score expiration (cleanup old data)
    reasons JSONB DEFAULT '[]'::JSONB,               -- Array of threat reasons with timestamps
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),      -- First time IP was tracked
    request_count INTEGER NOT NULL DEFAULT 0,         -- Total requests from this IP

    -- Performance indexes
    INDEX idx_threat_scores_expires (expires_at),    -- Cleanup expired scores
    INDEX idx_threat_scores_score (score DESC)        -- High-risk IP reports
);

-- ============================================================================
-- TABLE: security_events
-- PURPOSE: Audit log of all security events for compliance and forensics
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,                         -- Auto-incrementing event ID
    event_type VARCHAR(50) NOT NULL,                  -- Event type (scan, honeypot, ban, sql_injection, xss, etc.)
    ip VARCHAR(45) NOT NULL,                          -- Client IP
    event_data JSONB NOT NULL DEFAULT '{}'::JSONB,   -- Event details (flexible schema)
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',   -- Severity: low, medium, high, critical
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),      -- Event timestamp

    -- Performance indexes
    INDEX idx_security_events_ip_time (ip, created_at DESC),       -- IP-specific event timeline
    INDEX idx_security_events_type_time (event_type, created_at DESC), -- Events by type over time
    INDEX idx_security_events_severity (severity, created_at DESC),    -- Critical events
    INDEX idx_security_events_time (created_at DESC)                   -- Recent events
);

-- GIN index for JSONB queries (analytics, forensics)
CREATE INDEX IF NOT EXISTS idx_security_events_data_gin ON security_events USING GIN (event_data);

-- ============================================================================
-- TABLE: request_counts
-- PURPOSE: Rate limiting counters (hot data, frequently updated)
-- ============================================================================
CREATE TABLE IF NOT EXISTS request_counts (
    ip VARCHAR(45) NOT NULL PRIMARY KEY,              -- Client IP
    count INTEGER NOT NULL DEFAULT 0,                 -- Request count in current window
    window_start TIMESTAMP NOT NULL DEFAULT NOW(),    -- Window start time
    expires_at TIMESTAMP NOT NULL,                    -- Cleanup expired counters

    -- Performance indexes
    INDEX idx_request_counts_expires (expires_at)    -- Cleanup expired entries
);

-- ============================================================================
-- TABLE: bot_verifications
-- PURPOSE: Persistent bot verification cache (DNS lookups are expensive)
-- ============================================================================
CREATE TABLE IF NOT EXISTS bot_verifications (
    ip VARCHAR(45) NOT NULL PRIMARY KEY,              -- Bot IP
    is_legitimate BOOLEAN NOT NULL,                   -- Verification result
    hostname VARCHAR(255),                            -- Reverse DNS hostname
    bot_type VARCHAR(50),                             -- Bot type (googlebot, bingbot, etc.)
    metadata JSONB DEFAULT '{}'::JSONB,              -- Additional bot data
    verified_at TIMESTAMP NOT NULL DEFAULT NOW(),     -- Verification timestamp
    expires_at TIMESTAMP NOT NULL,                    -- Cache expiration

    -- Performance indexes
    INDEX idx_bot_verifications_expires (expires_at), -- Cleanup expired verifications
    INDEX idx_bot_verifications_type (bot_type)       -- Bot analytics
);

-- ============================================================================
-- CLEANUP FUNCTIONS (CRON/SCHEDULED)
-- ============================================================================

-- Function: Cleanup expired bans
-- Usage: Run daily via cron
CREATE OR REPLACE FUNCTION cleanup_expired_bans() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM ip_bans WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Cleanup expired threat scores
-- Usage: Run daily via cron
CREATE OR REPLACE FUNCTION cleanup_expired_threat_scores() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM threat_scores WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Cleanup old security events
-- Usage: Run weekly (keep 90 days of events for compliance)
CREATE OR REPLACE FUNCTION cleanup_old_security_events(retention_days INTEGER DEFAULT 90) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '1 day' * retention_days;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Cleanup expired request counts
-- Usage: Run hourly
CREATE OR REPLACE FUNCTION cleanup_expired_request_counts() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM request_counts WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Cleanup expired bot verifications
-- Usage: Run daily
CREATE OR REPLACE FUNCTION cleanup_expired_bot_verifications() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM bot_verifications WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- EXAMPLE CRON SCHEDULE (PostgreSQL pg_cron extension or external cron)
-- ============================================================================
--
-- # Daily cleanup (3:00 AM)
-- 0 3 * * * psql -U security_user -d security_db -c "SELECT cleanup_expired_bans();"
-- 0 3 * * * psql -U security_user -d security_db -c "SELECT cleanup_expired_threat_scores();"
-- 0 3 * * * psql -U security_user -d security_db -c "SELECT cleanup_expired_bot_verifications();"
--
-- # Hourly cleanup
-- 0 * * * * psql -U security_user -d security_db -c "SELECT cleanup_expired_request_counts();"
--
-- # Weekly cleanup (Sunday 2:00 AM)
-- 0 2 * * 0 psql -U security_user -d security_db -c "SELECT cleanup_old_security_events(90);"
--
-- ============================================================================
-- ANALYTICS VIEWS (OPTIONAL)
-- ============================================================================

-- View: Recent high-risk IPs
CREATE OR REPLACE VIEW high_risk_ips AS
SELECT
    ip,
    score,
    last_updated,
    request_count,
    (SELECT COUNT(*) FROM ip_bans WHERE ip_bans.ip = threat_scores.ip) AS ban_count,
    reasons
FROM threat_scores
WHERE score >= 50 AND expires_at > NOW()
ORDER BY score DESC, last_updated DESC
LIMIT 1000;

-- View: Security event summary (last 24 hours)
CREATE OR REPLACE VIEW security_events_24h AS
SELECT
    event_type,
    COUNT(*) AS event_count,
    COUNT(DISTINCT ip) AS unique_ips,
    MIN(created_at) AS first_seen,
    MAX(created_at) AS last_seen
FROM security_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY event_count DESC;

-- View: Top banned IPs (repeat offenders)
CREATE OR REPLACE VIEW top_banned_ips AS
SELECT
    ip,
    COUNT(*) AS ban_count,
    MAX(banned_at) AS last_banned,
    MIN(banned_at) AS first_banned,
    ARRAY_AGG(DISTINCT reason ORDER BY reason) AS ban_reasons
FROM ip_bans
WHERE expires_at > NOW()
GROUP BY ip
HAVING COUNT(*) > 1
ORDER BY ban_count DESC, last_banned DESC
LIMIT 100;

-- ============================================================================
-- DEPLOYMENT NOTES
-- ============================================================================
--
-- 1. Create database user:
--    CREATE USER security_user WITH PASSWORD 'your_secure_password';
--    GRANT ALL PRIVILEGES ON DATABASE security_db TO security_user;
--
-- 2. Run this schema:
--    psql -U security_user -d security_db -f database/schema.sql
--
-- 3. Configure DatabaseStorage with PDO:
--    $pdo = new PDO('pgsql:host=localhost;dbname=security_db', 'security_user', 'password');
--    $storage = new DatabaseStorage($pdo, $redis);
--
-- 4. Setup cron jobs for cleanup (see EXAMPLE CRON SCHEDULE above)
--
-- 5. Monitor table sizes:
--    SELECT relname AS table_name,
--           pg_size_pretty(pg_total_relation_size(relid)) AS size
--    FROM pg_catalog.pg_statio_user_tables
--    WHERE relname LIKE 'security_%' OR relname IN ('ip_bans', 'threat_scores', 'request_counts', 'bot_verifications')
--    ORDER BY pg_total_relation_size(relid) DESC;
--
-- ============================================================================
