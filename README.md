# Security Shield

[![PHP Version](https://img.shields.io/badge/PHP-%5E8.1-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Security Middleware for PHP 8.1+**

Honeypot, scanner detection, and resilience patterns for PHP applications.

---

## What This Package Does

- **Honeypot System** - 69 trap endpoints to catch scanners (/.env, /wp-admin, etc.)
- **Scanner Detection** - Identifies sqlmap, nikto, masscan by signatures
- **Rate Limiting** - 4 algorithms: sliding window, token bucket, leaky bucket, fixed window
- **IP Scoring** - Accumulates threat scores based on behavior
- **Bot Verification** - DNS-based verification for Googlebot, Bingbot
- **Geo-Blocking** - Country-level restrictions via external GeoIP provider

## What This Package Does NOT Do

- **Not a WAF** - No SQL injection, XSS, or OWASP Top 10 detection
- **Not DDoS Protection** - Cannot handle volumetric attacks (use Cloudflare/AWS Shield)
- **Not ML-Based** - No machine learning, just signature and statistical detection
- **Not Penetration Tested** - Has not undergone professional security audit

**Use alongside a real WAF (ModSecurity, Cloudflare) for production.**

---

## Architecture

### Resilience Patterns

| Pattern | Description | Storage Required |
|---------|-------------|------------------|
| Circuit Breaker | Fail fast when dependency is down | Redis (distributed) or none (local) |
| Retry Policy | Exponential backoff with jitter | None |
| Fallback Chain | Try providers in order until success | None |
| Bulkhead | Limit concurrent executions | Redis |

### Observability

| Component | Format | Notes |
|-----------|--------|-------|
| Tracing | OpenTelemetry-compatible | W3C traceparent context propagation |
| Metrics | Prometheus text format | Counters, gauges, histograms |
| Health | JSON + HTTP status | Liveness/readiness for Kubernetes |

### Anomaly Detection

| Detector | What It Detects |
|----------|-----------------|
| Statistical | Values outside Z-score threshold |
| Rate | Request rate spikes/drops |
| Pattern | Unusual paths, methods, user agents |
| Time-Based | Activity during unusual hours |

---

## Installation

```bash
composer require senza1dio/security-shield
```

## Quick Start

### Option 1: No Dependencies (Development/Testing)

```php
<?php
use Senza1dio\SecurityShield\Middleware\SecurityMiddleware;
use Senza1dio\SecurityShield\Config\SecurityConfig;
use Senza1dio\SecurityShield\Storage\NullStorage;

// In-memory storage - NO Redis/Database required
$config = (new SecurityConfig())
    ->setStorage(new NullStorage());

$security = new SecurityMiddleware($config);

if (!$security->handle($_SERVER)) {
    http_response_code(403);
    exit('Access Denied');
}
```

**Note**: NullStorage loses data between requests. Use for testing only.

### Option 2: Database Storage (Production without Redis)

```php
<?php
use Senza1dio\SecurityShield\Storage\DatabaseStorage;

// Use your existing database - NO Redis required
$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');

$config = (new SecurityConfig())
    ->setStorage(new DatabaseStorage($pdo));

$security = new SecurityMiddleware($config);

if (!$security->handle($_SERVER)) {
    http_response_code(403);
    exit('Access Denied');
}
```

### Option 3: Redis Storage (Recommended for Production)

```php
<?php
use Senza1dio\SecurityShield\Storage\RedisStorage;

// Fastest option - requires ext-redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$config = (new SecurityConfig())
    ->setStorage(new RedisStorage($redis));

$security = new SecurityMiddleware($config);

if (!$security->handle($_SERVER)) {
    http_response_code(403);
    exit('Access Denied');
}
```

---

## Usage Examples

### Circuit Breaker

```php
use Senza1dio\SecurityShield\Resilience\CircuitBreaker;

$breaker = new CircuitBreaker('redis', $storage, [
    'failure_threshold' => 5,    // Open after 5 failures
    'recovery_timeout' => 30,    // Try again after 30s
    'half_open_max_calls' => 3,  // Allow 3 test calls
]);

// State logged to error_log on transitions
$result = $breaker->call(
    fn() => $redis->get('key'),
    fn() => 'fallback-value'
);
```

**Limitation:** In PHP-FPM, each worker has independent in-memory state if Redis unavailable.

### Retry Policy

```php
use Senza1dio\SecurityShield\Resilience\RetryPolicy;

$policy = RetryPolicy::exponentialBackoffWithJitter(
    maxAttempts: 5,
    baseDelay: 1.0,
    maxDelay: 30.0
);

// Delays: ~1s, ~2s, ~4s, ~8s (with random jitter)
$result = $policy->execute(fn() => $api->call());
```

### Rate Limiting

```php
use Senza1dio\SecurityShield\RateLimiting\RateLimiter;

// Token bucket: 100 tokens, refills 10/second
$limiter = RateLimiter::tokenBucket($storage, 100, 10);

$result = $limiter->attempt('user:123');
if (!$result->allowed) {
    // $result->retryAfter contains seconds to wait
    http_response_code(429);
    exit;
}
```

### Health Checks

```php
use Senza1dio\SecurityShield\Health\HealthCheck;
use Senza1dio\SecurityShield\Health\Checks\RedisHealthCheck;

$health = new HealthCheck();
$health->addCheck('redis', new RedisHealthCheck($redis));

// Returns HealthResult with HTTP status code
$result = $health->readiness();

header('Content-Type: application/json');
http_response_code($result->getHttpStatusCode());
echo $result->toJson();
```

### Distributed Tracing

```php
use Senza1dio\SecurityShield\Telemetry\Tracer;
use Senza1dio\SecurityShield\Telemetry\SpanKind;

$tracer = new Tracer('my-service', '1.0.0');

// Extract parent context from incoming request
$parentContext = $tracer->extractContext(getallheaders());

$span = $tracer->startSpanFromContext('handle-request', $parentContext, SpanKind::SERVER);
$span->setAttribute('http.method', $_SERVER['REQUEST_METHOD']);

// ... process request ...

$span->setStatus(SpanStatus::OK);
$tracer->endSpan($span);
$tracer->flush(); // Export spans
```

### Hot-Reload Configuration

```php
use Senza1dio\SecurityShield\Config\ConfigProvider;

$config = new ConfigProvider($storage, [
    'cache_ttl' => 60,  // Reload from Redis every 60s
]);

$config->setDefaults(['threshold' => 50]);

// Update from anywhere - all instances pick up changes
$config->setRemote('threshold', 100);

// Later reads get new value after cache expires
$value = $config->get('threshold'); // 100
```

**Note:** Changes propagate on cache expiry, not instantly.

---

## Notifications

```php
use Senza1dio\SecurityShield\Notifications\NotificationManager;
use Senza1dio\SecurityShield\Notifications\TelegramNotifier;
use Senza1dio\SecurityShield\Notifications\SlackNotifier;

$manager = new NotificationManager();
$manager->addChannel(new TelegramNotifier($botToken, $chatId));
$manager->addChannel(new SlackNotifier($webhookUrl));

// Send to all channels
$result = $manager->broadcast('Security Alert', 'IP banned: 1.2.3.4', [
    'reason' => 'Honeypot access',
]);

// Check results
if (!$result->allSuccessful()) {
    foreach ($result->getErrors() as $channel => $error) {
        error_log("Notification to {$channel} failed: {$error}");
    }
}
```

---

## Configuration Validation

```php
use Senza1dio\SecurityShield\Config\ConfigValidator;

$validator = ConfigValidator::create()
    ->required()
    ->type('integer')
    ->min(1)
    ->max(1000);

$result = $validator->validate($value);
if (!$result->valid) {
    throw new InvalidArgumentException($result->error);
}
```

---

## Requirements

- PHP 8.1+ (uses enums, readonly properties)
- ext-json

### Optional Extensions
- ext-redis (for RedisStorage - recommended for production)
- ext-pdo (for DatabaseStorage)
- ext-curl (for notification channels, GeoIP)

---

## Storage Backends

**Choose the right storage for your use case:**

| Backend | Use Case | Dependencies | Performance | Persistence |
|---------|----------|--------------|-------------|-------------|
| **NullStorage** | Testing, Development | ✅ None | ~0.001ms | ❌ No (in-memory) |
| **DatabaseStorage** | Production (no Redis) | `ext-pdo` | ~1-5ms | ✅ Yes (MySQL/PostgreSQL) |
| **RedisStorage** | Production (recommended) | `ext-redis` | ~0.05ms | ✅ Yes (distributed) |

### When to Use Each Backend

**NullStorage** - Development/Testing Only
```php
$config = (new SecurityConfig())->setStorage(new NullStorage());
```
- ✅ Zero setup, no dependencies
- ✅ Perfect for unit tests
- ❌ Data lost between requests
- ❌ NOT for production

**DatabaseStorage** - Production without Redis
```php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
$config = (new SecurityConfig())->setStorage(new DatabaseStorage($pdo));
```
- ✅ No extra infrastructure needed
- ✅ Uses existing database
- ✅ Persistent across servers
- ⚠️ Slower than Redis (1-5ms vs 0.05ms)

**RedisStorage** - Production (Best Performance)
```php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$config = (new SecurityConfig())->setStorage(new RedisStorage($redis));
```
- ✅ Ultra-fast (~0.05ms)
- ✅ Distributed state across servers
- ✅ Built-in TTL expiration
- ⚠️ Requires Redis server

---

## Known Limitations

1. **No Persistence in NullStorage** - Data lost between requests
2. **Clock Skew** - Rate limiting assumes synchronized clocks
3. **Memory Growth** - Tracer spans queue in memory until flush
4. **Blocking Operations** - SMTP notifications block during send
5. **No Clustering** - Each PHP worker has independent memory state

---

## Error Handling

All network operations log errors to `error_log()`:
- SMTP failures
- Webhook failures
- Redis connection issues
- Circuit breaker state changes

Configure PHP error_log to capture these in production.

---

## Testing

```bash
composer install
composer test          # PHPUnit tests
composer stan          # PHPStan level 8
composer cs-check      # Code style check
```

---

## License

MIT License - see [LICENSE](LICENSE)
