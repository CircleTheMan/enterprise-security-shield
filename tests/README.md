# Security Shield - Test Suite

## Overview

This directory contains **TWO test suites**:

1. **Basic Tests** (`WooCommerceSecurityTest.php`) - Fast, no setup required, uses NullStorage
2. **Real Storage Tests** (`WooCommerceRealStorageTest.php`) - Slow, requires PostgreSQL, uses DatabaseStorage

## ⚠️ CRITICAL DIFFERENCE

### Basic Tests (NullStorage)
- ✅ **PRO**: Fast (< 1 second), no dependencies
- ❌ **CON**: NullStorage does NOT persist data
- ❌ **CON**: Rate limiting is FAKE (storage doesn't save request counts)
- ❌ **CON**: Score accumulation is FAKE (scores don't persist)
- ❌ **CON**: Bans are FAKE (bans aren't enforced across requests)

**Result**: Basic tests verify LOGIC but NOT real-world functionality.

### Real Storage Tests (DatabaseStorage)
- ✅ **PRO**: Tests REAL functionality with persistent storage
- ✅ **PRO**: Rate limiting ACTUALLY works
- ✅ **PRO**: Score accumulation persists across requests
- ✅ **PRO**: Bans are ENFORCED for subsequent requests
- ❌ **CON**: Requires PostgreSQL setup
- ❌ **CON**: Slower (database I/O)

**Result**: Real storage tests verify PRODUCTION behavior.

---

## Quick Start (Basic Tests)

No setup required:

```bash
php tests/WooCommerceSecurityTest.php
```

**Expected output:**
```
✅ PASS: Whitelist IP bypasses ALL checks
✅ PASS: Non-whitelisted IP accessing suspicious path gets scored
✅ PASS: Legitimate request (not suspicious path) is allowed
✅ PASS: wp-config.php access gets critical score (50 points = instant ban)
✅ PASS: WooCommerce REST API path is detected as suspicious
✅ PASS: Parent WAF scanner detection still works
✅ PASS: CIDR range whitelist works correctly

Passed: 7
Failed: 0
```

---

## Real Storage Tests Setup (PostgreSQL)

### Step 1: Start PostgreSQL

**Option A: Docker**
```bash
docker run -d \
  --name security_shield_postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:16-alpine
```

**Option B: OrbStack** (if you have it)
```bash
# OrbStack PostgreSQL is already running on port 5432
docker ps | grep postgres
```

### Step 2: Create Test Database

```bash
# Using Docker container
docker exec -i security_shield_postgres psql -U postgres < tests/setup-test-db.sql

# OR using local psql client
psql -U postgres -h localhost -f tests/setup-test-db.sql
```

**Expected output:**
```
DROP DATABASE
DROP ROLE
CREATE ROLE
CREATE DATABASE
...
Test database setup complete!
```

### Step 3: Run Real Storage Tests

```bash
php tests/WooCommerceRealStorageTest.php
```

**Expected output:**
```
✅ Connected to PostgreSQL test database

🧹 Cleaning up previous test data...
✅ Test data cleaned

✅ PASS: Rate limiting: Checkout allows 5 requests then blocks
✅ PASS: Rate limiting: Add to cart allows 30 requests then blocks
✅ PASS: Score accumulation: Multiple suspicious paths lead to ban
✅ PASS: Ban persistence: Once banned, IP stays banned across requests
✅ PASS: Whitelist bypass: Whitelisted IP passes even with suspicious paths
✅ PASS: Rate limiting: Coupon checks allow 10 requests then block

🧹 Cleaning up test data...
✅ Test data cleaned

=== Test Results ===
Passed: 6
Failed: 0

✅ ALL TESTS PASSED - WooCommerce integration is SOLID!
```

---

## Troubleshooting

### Error: Cannot connect to PostgreSQL

**Symptom:**
```
❌ CRITICAL: Cannot connect to PostgreSQL: SQLSTATE[08006] [7] connection to server at "localhost" (::1), port 5432 failed
```

**Fix:**
1. Check if PostgreSQL is running: `docker ps | grep postgres`
2. If not running, start it (see Step 1 above)
3. Check port 5432 is not in use: `lsof -i :5432`

### Error: Database does not exist

**Symptom:**
```
❌ CRITICAL: Cannot connect to PostgreSQL: SQLSTATE[08006] database "security_shield_test" does not exist
```

**Fix:**
Run the setup SQL script (see Step 2 above)

### Error: Permission denied

**Symptom:**
```
ERROR:  permission denied for table security_events
```

**Fix:**
Re-run the setup script - it grants all permissions to `shield_test_user`

---

## What Each Test Suite Validates

### Basic Tests (7 tests)
1. Whitelist bypass works (IP whitelisting logic)
2. Non-whitelisted IPs get scored (path detection)
3. Legitimate requests pass (no false positives)
4. wp-config.php = instant ban (critical path detection)
5. WooCommerce REST API detection (API path matching)
6. Parent WAF scanner detection (NULL user agent)
7. CIDR whitelist works (IP range matching)

### Real Storage Tests (6 tests)
1. **Checkout rate limiting**: 5 requests/5min, 6th blocked
2. **Add-to-cart rate limiting**: 30 requests/min, 31st blocked
3. **Score accumulation**: 20pt + 15pt + 20pt = 55pt → BANNED
4. **Ban persistence**: Banned IP blocked even for legitimate requests
5. **Whitelist bypass**: Whitelisted IP passes all suspicious paths
6. **Coupon rate limiting**: 10 requests/5min, 11th blocked

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Shield Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: postgres
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          extensions: pgsql, pdo_pgsql

      - name: Install dependencies
        run: composer install --no-interaction

      - name: Setup test database
        run: psql -U postgres -h localhost -f tests/setup-test-db.sql
        env:
          PGPASSWORD: postgres

      - name: Run basic tests
        run: php tests/WooCommerceSecurityTest.php

      - name: Run real storage tests
        run: php tests/WooCommerceRealStorageTest.php
```

---

## Cleanup

To remove the test database:

```bash
# Drop test database and user
psql -U postgres -c "DROP DATABASE IF EXISTS security_shield_test;"
psql -U postgres -c "DROP USER IF EXISTS shield_test_user;"
```

---

## Best Practices

1. **Always run BOTH test suites** before committing
2. Basic tests verify logic, real storage tests verify functionality
3. If basic tests pass but real storage tests fail → storage integration bug
4. If both fail → core logic bug
5. Never commit if ANY test fails

---

## Test Data

Tests use IPs in the `192.0.2.0/24` range (TEST-NET-1, RFC 5737):
- Safe for testing (never routed on the internet)
- Automatically cleaned up after tests
- Each test uses a different IP (192.0.2.10, 192.0.2.20, etc.)
