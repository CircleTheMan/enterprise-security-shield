-- ============================================================================
-- Test Database Setup for WooCommerce Security Shield Tests
-- ============================================================================
-- This script creates a dedicated test database for running real storage tests
-- WITHOUT interfering with production databases.
--
-- USAGE:
-- 1. Start PostgreSQL (Docker or OrbStack)
-- 2. Run: psql -U postgres -f tests/setup-test-db.sql
-- 3. Run tests: php tests/WooCommerceRealStorageTest.php
-- ============================================================================

-- Drop existing test database if exists
DROP DATABASE IF EXISTS security_shield_test;
DROP USER IF EXISTS shield_test_user;

-- Create test user
CREATE USER shield_test_user WITH PASSWORD 'test_password_123';

-- Create test database
CREATE DATABASE security_shield_test
    WITH OWNER = shield_test_user
    ENCODING = 'UTF8'
    TEMPLATE = template0;

-- Connect to test database
\c security_shield_test

-- ============================================================================
-- SECURITY EVENTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_events_ip ON security_events(ip);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_created ON security_events(created_at);

-- ============================================================================
-- IP BANS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_bans (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255) DEFAULT '',
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ban_count INTEGER DEFAULT 1
);

CREATE INDEX idx_ip_bans_ip ON ip_bans(ip);
CREATE INDEX idx_ip_bans_expires ON ip_bans(expires_at);

-- ============================================================================
-- IP SCORES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_scores (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    score INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_ip_scores_ip ON ip_scores(ip);
CREATE INDEX idx_ip_scores_expires ON ip_scores(expires_at);

-- ============================================================================
-- REQUEST COUNTS TABLE (for rate limiting)
-- ============================================================================
CREATE TABLE IF NOT EXISTS request_counts (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    request_type VARCHAR(50) DEFAULT 'general' NOT NULL,
    count INTEGER DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(ip, request_type)  -- CRITICAL: Separate counters per action type
);

CREATE INDEX idx_request_counts_ip ON request_counts(ip);
CREATE INDEX idx_request_counts_type ON request_counts(request_type);
CREATE INDEX idx_request_counts_expires ON request_counts(expires_at);

-- Grant permissions to test user
GRANT ALL PRIVILEGES ON DATABASE security_shield_test TO shield_test_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO shield_test_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO shield_test_user;

-- ============================================================================
-- VERIFICATION
-- ============================================================================
\dt
\du

SELECT 'Test database setup complete!' AS status;
